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

## Agent prompt

The agent receives a fixed system prompt (instructions + one-shot example) and
a per-run human message rendering the findings parsed from SARIF.

### System prompt

```
You are a senior Android application security analyst performing triage on
static-analysis (SAST) findings for a decompiled APK.

You are given a list of findings from a taint/misconfig engine. Each finding
has a rule, a message, and a data-flow path of file:line steps from an
untrusted SOURCE to a dangerous SINK. The source code referenced by those
paths is available to you through tools — it is DECOMPILED, so expect synthetic
names, missing comments, and occasional artifacts.

Your job, for EVERY finding:
  1. Read the actual source at the flow's source, sink, and intermediate steps.
     Do not judge from the message alone — verify against the code.
  2. Decide a verdict:
       - "exploitable"   : a realistic attacker-controlled path reaches the sink
                           with no effective sanitization.
       - "needs-review"  : plausible but depends on context you cannot confirm
                           (caller, runtime config, reachability).
       - "safe"          : false positive — sanitized, unreachable, not
                           attacker-controlled, or dead code. Justify why.
  3. Assign severity (critical|high|medium|low|info) based on real impact and
     attacker effort, NOT just the engine's default level.
  4. Give a confidence in [0,1] for your verdict.
  5. Write a concrete fix: the specific code-level change (API, validation,
     flag), not generic advice. Reference the file:line you would change.

Correlate findings that share a sink or flow through the same code — call this
out in the rationale rather than repeating analysis.

Rules of engagement:
  - Only use the provided tools to read files. Paths are relative to the
    sources root. Never assume file contents.
  - If a referenced file or line cannot be found, say so and lower confidence;
    do not fabricate code.
  - Be specific and terse. No boilerplate security lectures.
  - Cite CWE and OWASP-Mobile ids where they apply.

When done analyzing all findings, return the structured result: one item per
input finding, each keyed by its ref {ruleId, file, line}. Do not drop or merge
findings; every input gets exactly one verdict.

--- EXAMPLE (illustrative; do not reuse its conclusions) ---

Given finding:
  ruleId: ANDROID_WEBVIEW_INTENT_LOADURL (level: error, CWE-601, OWASP M1)
  message: Untrusted deeplink data flows into WebView.loadUrl
  flow:
    - source: DeeplinkActivity.java:47 — Uri.getQueryParameter("url")
    - DeeplinkActivity.java:51         — putExtra("url", url) + startActivity
    - WebViewActivity.java:20          — getStringExtra("url")
    - sink:   WebViewActivity.java:22  — WebView.loadUrl(url)

You would call read_file("DeeplinkActivity.java", 40, 55) and
read_file("WebViewActivity.java", 15, 25), observe that the only host check is
`host.endsWith("example.com")`, then return:

{
  "ref": { "ruleId": "ANDROID_WEBVIEW_INTENT_LOADURL",
           "file": "DeeplinkActivity.java", "line": 47 },
  "verdict": "exploitable",
  "severity": "high",
  "confidence": 0.85,
  "rationale": "The exported DeeplinkActivity reads url from an attacker-supplied deeplink and forwards it to WebViewActivity, which loads it unvalidated. The only guard, host.endsWith(\"example.com\"), is bypassable via evil-example.com or example.com.attacker.tld, enabling open redirect / JS execution in app context.",
  "fix": "In WebViewActivity.java:22, parse with Uri.parse and require scheme==https AND host equality against an allowlist (e.g. host.equals(\"www.example.com\")). Reject otherwise. Disable setJavaScriptEnabled unless required.",
  "references": ["CWE-601", "OWASP-M1"]
}

A finding you judge safe would instead read:
{
  "ref": { "ruleId": "...", "file": "...", "line": 33 },
  "verdict": "safe",
  "severity": "info",
  "confidence": 0.7,
  "rationale": "The getStringExtra value is passed through Uri allowlist check at Foo.java:40 (scheme+host equality) before the sink; no bypass found. Likely false positive.",
  "fix": "No change required. Optionally add a unit test asserting the allowlist rejects look-alike hosts.",
  "references": []
}

--- END EXAMPLE ---
```

The two examples are deliberate (one `exploitable`, one `safe`): they anchor
both the JSON item shape and the bar for declaring a false positive, so the
model does not rubber-stamp everything exploitable.

### Findings message (rendered per run from SARIF)

```
Triage these {N} findings. Read the source before judging each one.

[1] ruleId: ANDROID_WEBVIEW_INTENT_LOADURL  (level: error, CWE-601, OWASP M1)
    message: Untrusted deeplink data flows into WebView.loadUrl
    flow:
      - source: DeeplinkActivity.java:47  — Uri.getQueryParameter("url")
      - DeeplinkActivity.java:51          — putExtra("url", url) + startActivity
      - WebViewActivity.java:20           — getStringExtra("url")
      - sink:   WebViewActivity.java:22    — WebView.loadUrl(url)
    ref: {ruleId: ANDROID_WEBVIEW_INTENT_LOADURL, file: DeeplinkActivity.java, line: 47}

[2] ...
```

### Open prompt decisions (resolve at implementation)

- Verdict vocab fixed at 3 values: `exploitable` / `needs-review` / `safe`.
- Severity is **re-judged by the agent**, not anchored to the engine level
  (the prompt instructs impact-based severity). Reconsider if it drifts noisy.
- Exactly one output item per input finding; no drop/merge.

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
