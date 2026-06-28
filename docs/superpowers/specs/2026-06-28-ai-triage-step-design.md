# AI Triage Step — Design

Date: 2026-06-28
Status: Approved (design)
Branch: feat/interproc-taint-and-rules

## Goal

Add a non-Java pipeline step: an AI agent that reads the generated report
together with the decompiled source and produces a human-readable analysis of
each finding — severity judgement, exploitability verdict, and concrete fix
suggestions — or marks the finding safe (false positive). The agent runs in a
ReAct loop and reads source files referenced by the findings.

## Decisions (from brainstorming)

| Question | Decision |
|----------|----------|
| Output destination | **Separate sidecar artifact** (JSON + Markdown). Reporter untouched. |
| Granularity | **One agent, all findings.** Single ReAct loop, correlates shared sinks. |
| LLM provider | **OpenRouter** (OpenAI-compatible). `langchain-openai` pointed at `https://openrouter.ai/api/v1`. |
| Gating | **Always-on, fail-soft.** Missing key / error → empty sidecar + warning, workflow succeeds. |
| Placement | **After `report`, sequential.** AI consumes the report. |
| Report input | **SARIF** (structured JSON), not HTML. |
| Integration | **Approach A**: Java activity shells out to a Python CLI via `ProcessBuilder`. No Temporal Python worker. |

## Architecture

The language boundary is the existing artifact root on disk. Every other step
already addresses inputs/outputs by artifact key resolved to a filesystem path
(`ActivityPathResolver`). The Python step reads the same paths and writes its
output back, so no new transport or serialization layer is needed.

```
... taint + misconfig (parallel)
      └─ Promise.allOf ─> report (HTML + SARIF)
                            └─ aiTriage (NEW, sequential)
                                  reads: SARIF + decompiled sources
                                  writes: ai-triage.json + ai-triage.md
```

`AnalysisResult` gains `aiTriageJsonKey` and `aiTriageMdKey`.

### Java side

New activity on `PipelineActivities`:

```java
AiTriageArtifacts aiTriage(AiTriageActivityInput input);
```

- `AiTriageActivityInput(String sarifKey, String sourcesDirKey,
   String outJsonKey, String outMdKey)`
- `AiTriageArtifacts(String jsonKey, String mdKey)`

`PipelineActivitiesImpl.aiTriage` resolves keys → paths and delegates to a new
`StepApis.aiTriage(Path sarif, Path sourcesDir, Path outJson, Path outMd)`
method (so tests inject a fake; production shells out).

Production `ProductionStepApis.aiTriage` runs:

```
python3 -m sast_ai_triage \
    --sarif   <sarif.json> \
    --sources <decompiled-dir> \
    --out-json <ai-triage.json> \
    --out-md   <ai-triage.md>
```

via `ProcessBuilder`, inheriting `OPENROUTER_API_KEY` and `OPENROUTER_MODEL`
from the environment. Interpreter and module entrypoint are resolved from
config with sane defaults (`python3`, `sast_ai_triage`); a
`SAST_AI_TRIAGE_CMD` env override allows pointing at a venv.

**Fail-soft (Java owns the guarantee):** if the interpreter is missing, the
process exits non-zero, or no output file is produced, the activity writes an
empty sidecar (`{"items": [], "summary": "AI triage skipped"}` + a short MD
note), logs a warning, and returns the keys normally. The workflow always
succeeds. Mirrors the `AndroidPlatform.resolve()` fail-soft pattern already in
the parse step.

Temporal note: the activity keeps the default retry options. Because fail-soft
swallows errors into a successful empty result, retries do not fire on a
missing key — intended. A genuinely transient API error inside Python is
retried at the LLM-call level (see below), not by Temporal.

### Python side — `apps/ai-triage/`

Lives outside the Gradle build. Gradle stays Java-only; the orchestrator only
invokes the interpreter. Packaged with `pyproject.toml`; a documented
`python -m venv` + `pip install -e .` setup.

Modules:

- `cli.py` — argparse entrypoint. Parses SARIF, builds the findings list,
  invokes the agent, writes `--out-json` and `--out-md`. Defensive: on any
  unhandled error or missing API key it still writes a valid empty sidecar and
  exits 0 (Java fail-soft is the backstop, not the only line of defense).
- `sarif.py` — parse `runs[0].results[]` into internal `Finding` objects:
  `ruleId`, `level`, `message`, `flow[]` (from
  `codeFlows[0].threadFlows[0].locations[]`: `file` = `physicalLocation.
  artifactLocation.uri`, `line` = `region.startLine`, `label` =
  `location.message.text`), plus `cwe`/`owaspMobile` looked up from
  `driver.rules[].properties` by `ruleId`. `ref` = `{ruleId, file, line}` of
  the first flow step (findings have no stable id).
- `agent.py` — one LangChain ReAct loop (langgraph `create_react_agent`) over a
  `ChatOpenAI(base_url=<openrouter>, model=<env>)`. The findings list is
  rendered into the initial human message; the agent reads source as needed via
  tools, then emits the structured result.
- `tools.py` — filesystem tools **jailed to the sources dir**, every relpath
  resolved and checked to stay under the root (path-traversal guard):
  - `read_file(relpath, start=None, end=None)` — returns file slice with line numbers.
  - `list_dir(relpath=".")` — lists a directory.
  - `search_code(query)` — substring/regex search across sources (bounded result count).
- `schema.py` — output model + validation.

LLM retry: wrap the model with a bounded retry (e.g. 2 attempts, exponential
backoff) for transient 429/5xx; on exhaustion, fall through to the empty
sidecar.

### Output schema

`ai-triage.json`:

```json
{
  "model": "openrouter/...",
  "generatedAt": "2026-06-28T12:00:00Z",
  "summary": "1 exploitable, 1 needs review.",
  "items": [
    {
      "ref": { "ruleId": "ANDROID_WEBVIEW_INTENT_LOADURL",
               "file": "DeeplinkActivity.java", "line": 47 },
      "verdict": "exploitable",
      "severity": "high",
      "confidence": 0.8,
      "rationale": "Untrusted deeplink query param reaches WebView.loadUrl; the host check host.endsWith(\"example.com\") is bypassable via evil-example.com.",
      "fix": "Validate with a strict allowlist of full hosts / use Uri parsing and compare host equality; reject non-https schemes.",
      "references": ["CWE-601", "https://owasp.org/..."]
    }
  ]
}
```

- `verdict` ∈ `exploitable` | `needs-review` | `safe`.
- `severity` ∈ `critical` | `high` | `medium` | `low` | `info`.
- `confidence` ∈ `[0,1]`.

`ai-triage.md`: human-readable rendering — summary header, then one section per
finding (ref, verdict badge, severity, rationale, fix, references).

Structured output is obtained via the model's tool/function-calling
(`with_structured_output` against the Pydantic schema). On parse failure, retry
once with a "return valid JSON only" reminder, then fail-soft.

## Testing

- **Python (pytest), no network:**
  - `tools` path-jail guard rejects `../` escape and absolute paths outside root.
  - `sarif` parser maps the reporter's SARIF fixture to the expected findings + refs.
  - `schema` validation accepts a good object, rejects bad enums / out-of-range confidence.
  - agent flow with a **mocked LLM** (canned tool calls + final structured object) → asserts the written JSON/MD.
  - missing-key path writes a valid empty sidecar and exits 0.
- **Java:**
  - fake `StepApis` verifies `aiTriage` activity wiring (keys → paths → output keys).
  - fail-soft: fake that simulates a non-zero/empty run → activity returns empty sidecar keys, workflow result carries them.
- No real OpenRouter calls in any test.

## Out of scope (YAGNI)

- No Temporal Python worker / polyglot task queue.
- No merging AI output into the HTML/SARIF report.
- No per-finding parallel agents.
- No caching of LLM responses across runs.

## Files

New:
- `apps/ai-triage/pyproject.toml`
- `apps/ai-triage/src/sast_ai_triage/{__init__,__main__,cli,sarif,agent,tools,schema}.py`
- `apps/ai-triage/tests/...`
- `orchestrator/.../activities/AiTriageActivityInput.java`
- `orchestrator/.../activities/AiTriageArtifacts.java`

Changed:
- `orchestrator/.../activities/PipelineActivities.java` (+`aiTriage`)
- `orchestrator/.../activities/PipelineActivitiesImpl.java` (+impl, +`StepApis.aiTriage`, +`ProductionStepApis` ProcessBuilder)
- `orchestrator/.../workflow/AnalyzeApkWorkflowImpl.java` (call after `report`)
- `orchestrator/.../AnalysisResult.java` (+`aiTriageJsonKey`, +`aiTriageMdKey`)
- `orchestrator/.../AnalysisPlan.java` + `ArtifactKeys` (new artifact keys)
- README / docs: venv setup + env vars.
