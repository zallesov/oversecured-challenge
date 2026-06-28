# AI Triage Step — Design

Date: 2026-06-28
Status: Approved (design)
Branch: feat/interproc-taint-and-rules

## Goal

Add an AI agent pipeline step that reads the generated report together with the
decompiled source and produces a human-readable analysis of each finding —
severity judgement, exploitability verdict, and concrete fix suggestions — or
marks the finding safe (false positive). The agent runs in a ReAct
(tool-calling) loop and reads source files referenced by the findings.

## Decisions (from brainstorming)

| Question | Decision |
|----------|----------|
| Output destination | **Separate sidecar artifact** (JSON + Markdown). Reporter untouched. |
| Granularity | **One agent, all findings.** Single tool-calling loop, correlates shared sinks. |
| LLM provider | **OpenRouter** (OpenAI-compatible). `langchain4j-open-ai` with custom `baseUrl`. |
| Gating | **Always-on, fail-soft.** Missing key / error → empty sidecar + warning, workflow succeeds. |
| Placement | **After `report`, sequential.** AI consumes the report. |
| Report input | **SARIF** (structured JSON), not HTML. |
| Implementation | **LangChain4j (Java), in-process.** No Python, no subprocess, no Temporal Python worker. |

## Architecture

The AI step is an ordinary in-process Temporal activity, identical in shape to
the existing steps (decompile, parse, taint, misconfig, report). No language
boundary, no subprocess — the earlier Python/`ProcessBuilder` design was
dropped once LangChain4j was chosen. The agent runs in the same JVM and reads
the same artifact paths every other step uses.

```
... taint + misconfig (parallel)
      └─ Promise.allOf ─> report (HTML + SARIF)
                            └─ aiTriage (NEW, sequential, in-process)
                                  reads: SARIF + decompiled sources
                                  writes: ai-triage.json + ai-triage.md
```

`AnalysisResult` gains `aiTriageJsonKey` and `aiTriageMdKey`.

### New module — `apps/ai-triage/`

A Gradle Java module like the other `apps/*`. Depends on `common` (Finding /
Severity), `langchain4j`, `langchain4j-open-ai`, and Jackson (already used).

- `AiTriageAnalyzer` — entrypoint:
  `void run(Path sarif, Path sourcesDir, Path outJson, Path outMd)`.
  Parses SARIF → findings, builds the agent, runs it, writes JSON + MD.
  Owns the fail-soft logic (see below).
- `SarifFindings` — parse `runs[0].results[]` into internal records:
  `ruleId`, `level`, `message`, `flow[]` (from
  `codeFlows[0].threadFlows[0].locations[]`: `file` = `physicalLocation.
  artifactLocation.uri`, `line` = `region.startLine`, `label` =
  `location.message.text`), plus `cwe`/`owaspMobile` from
  `driver.rules[].properties` by `ruleId`. `ref` = `{ruleId, file, line}` of
  the first flow step (findings have no stable id).
- `SourceTools` — `@Tool`-annotated methods, **jailed to the sources dir**
  (every relpath resolved and checked to stay under the root; path-traversal
  guard):
  - `@Tool readFile(String relpath, Integer start, Integer end)` — file slice with line numbers.
  - `@Tool listDir(String relpath)` — directory listing.
  - `@Tool searchCode(String query)` — bounded substring/regex search across sources.
- `TriageAgent` — LangChain4j `AiServices` interface:
  ```java
  interface TriageAgent { TriageResult triage(String findings); }
  ```
  Built with the OpenRouter model + `SourceTools`; LangChain4j drives the
  tool-calling loop automatically.
- `TriageResult` / `TriageItem` — records used both as the structured-output
  target and the JSON artifact shape (Jackson-serialized).
- `MarkdownRenderer` — renders `TriageResult` → `ai-triage.md`.

Model wiring:

```java
ChatModel model = OpenAiChatModel.builder()
    .baseUrl("https://openrouter.ai/api/v1")
    .apiKey(System.getenv("OPENROUTER_API_KEY"))
    .modelName(System.getenv("OPENROUTER_MODEL"))
    .supportedCapabilities(RESPONSE_FORMAT_JSON_SCHEMA)
    .strictJsonSchema(true)
    .build();
TriageAgent agent = AiServices.builder(TriageAgent.class)
    .chatModel(model)
    .tools(new SourceTools(sourcesDir))
    .build();
```

Structured output: `.supportedCapabilities(RESPONSE_FORMAT_JSON_SCHEMA)` +
`.strictJsonSchema(true)` make LangChain4j derive a JSON schema from
`TriageResult` and force the model to fill it — no manual JSON parsing.

### Orchestrator wiring (Java)

New activity on `PipelineActivities`:

```java
AiTriageArtifacts aiTriage(AiTriageActivityInput input);
```

- `AiTriageActivityInput(String sarifKey, String sourcesDirKey,
   String outJsonKey, String outMdKey)`
- `AiTriageArtifacts(String jsonKey, String mdKey)`

`PipelineActivitiesImpl.aiTriage` resolves keys → paths and delegates to
`StepApis.aiTriage(Path sarif, Path sourcesDir, Path outJson, Path outMd)`
(fake in tests; production calls `new AiTriageAnalyzer().run(...)`, matching how
the reporter/misconfig steps call their app directly).

Workflow: after the `report` activity returns, call `aiTriage` with the report's
SARIF key + the sources dir key, then return both new keys in `AnalysisResult`.

### Fail-soft (always-on)

`AiTriageAnalyzer.run` is defensive end to end:

- No `OPENROUTER_API_KEY` → skip the model entirely, write an empty sidecar
  (`{"items": [], "summary": "AI triage skipped: no API key"}` + a short MD
  note), return normally.
- Any exception (network, API error, schema/parse failure) → log a warning,
  write the same empty sidecar, return normally.
- Transient model errors (429/5xx) get a bounded retry (≈2 attempts) before
  falling through to the empty sidecar.

The workflow therefore always succeeds and always produces both artifacts.
Mirrors the `AndroidPlatform.resolve()` fail-soft already used in the parse
step. Temporal retry options stay default; because fail-soft swallows errors
into a successful result, Temporal does not retry this activity.

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
finding (ref, verdict, severity, rationale, fix, references).

## Agent prompt

The agent receives a fixed system prompt (instructions + one-shot example,
supplied as the `@SystemMessage` of the `AiServices` interface) and a per-run
user message rendering the findings parsed from SARIF.

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

You would call readFile("DeeplinkActivity.java", 40, 55) and
readFile("WebViewActivity.java", 15, 25), observe that the only host check is
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

- **`apps/ai-triage` (Java), no network:**
  - `SourceTools` path-jail guard rejects `../` escape and absolute paths outside root.
  - `SarifFindings` maps the reporter's SARIF fixture to the expected findings + refs.
  - `MarkdownRenderer` renders a known `TriageResult` to expected MD.
  - agent flow with an injected **fake `ChatModel`** (canned tool calls + final structured object) → asserts written JSON/MD. `AiServices` accepts any `ChatModel`, so the model is mocked, never called over the network.
  - missing-key path writes a valid empty sidecar and returns normally.
- **Orchestrator (Java):**
  - fake `StepApis` verifies the `aiTriage` activity wiring (keys → paths → output keys) and that `AnalysisResult` carries both new keys.
  - fail-soft: fake that throws → activity still returns empty-sidecar keys; workflow succeeds.
- No real OpenRouter calls in any test.

## Out of scope (YAGNI)

- No Python / subprocess / Temporal Python worker.
- No merging AI output into the HTML/SARIF report.
- No per-finding parallel agents.
- No caching of LLM responses across runs.

## Files

New:
- `apps/ai-triage/build.gradle`
- `apps/ai-triage/src/main/java/com/oversecured/sast/aitriage/{AiTriageAnalyzer,SarifFindings,SourceTools,TriageAgent,TriageResult,TriageItem,MarkdownRenderer}.java`
- `apps/ai-triage/src/test/java/com/oversecured/sast/aitriage/...`
- `orchestrator/.../activities/AiTriageActivityInput.java`
- `orchestrator/.../activities/AiTriageArtifacts.java`

Changed:
- `settings.gradle` (+`apps:ai-triage`)
- `orchestrator/build.gradle` (+`apps:ai-triage` dependency)
- `orchestrator/.../activities/PipelineActivities.java` (+`aiTriage`)
- `orchestrator/.../activities/PipelineActivitiesImpl.java` (+impl, +`StepApis.aiTriage`, +`ProductionStepApis` call)
- `orchestrator/.../workflow/AnalyzeApkWorkflowImpl.java` (call after `report`)
- `orchestrator/.../AnalysisResult.java` (+`aiTriageJsonKey`, +`aiTriageMdKey`)
- `orchestrator/.../AnalysisPlan.java` + `ArtifactKeys` (new artifact keys)
- README / docs: `OPENROUTER_API_KEY` + `OPENROUTER_MODEL` env vars.
