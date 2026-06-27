# Android Taint SAST Pipeline — Design Spec

**Shared conventions:** [Shared Contracts and Naming Conventions](../reference/2026-06-27-shared-contracts-and-conventions.md)

**Date:** 2026-06-27
**Status:** Approved (design)
**Challenge:** OverSecured Coding Challenge, Part 2 — *"Implement a simple dataflow / taint SAST analysis for Android for one vulnerability class. The detection rules must not be hardcoded — they live in an external, abstract rules format."*

---

## 1. Goal & Scope

Build a SAST pipeline that takes an Android **APK**, decompiles it, runs a **taint / dataflow analysis** for one vulnerability class driven entirely by **external YAML rules**, and emits a human-readable **HTML** report plus a machine-readable **SARIF** report.

**Target vulnerability class:** `Intent / deeplink data → WebView.loadUrl` (open redirect / XSS, CWE-601).

A **second** class — `Uri path segment → file open` (path traversal, CWE-22) — is implemented as a separate YAML config on the **same** engine. The challenge requires only one class; the second exists solely to prove rules are external config, not code, and to exercise the parallel fan-out. The engine and pipeline are identical for both.

Rationale for this class:
- Exists in **both** OVAA and DroidBench (the privacy-leak `getDeviceId` class does **not** exist in OVAA, so it was dropped).
- Genuinely requires taint analysis, not grep: source and sink live in different classes/methods, connected through an `Intent` extra and a cross-component (deeplink) hop, with a bypassable sanitizer (`host.endsWith("example.com")`).
- Exercises the features that distinguish a real taint engine: extra/field propagation, light inter-component flow, sanitizer modeling, and exported-vs-non-exported reachability for false-positive reduction.

**Non-goals (challenge scope):** full IFDS/IDE solver, precise alias/points-to analysis, FlowDroid-style dummy-main lifecycle modeling, reflection, implicit flows, native code, dynamic loading. See §10.

---

## 2. Key Decisions

| Decision | Choice | Why |
|---|---|---|
| Analysis target | **jadx-decompiled Java source** | Closest to what a developer sees (challenge answer #1); demoable and hand-traceable. |
| Engine language | **Java + JavaParser + JavaSymbolSolver** | Source-first, tolerant of non-compiling decompiled code (fail-soft), modern Java (1–25), Apache-2.0. Symbol resolution distinguishes real `android.webkit.WebView.loadUrl` from look-alikes → higher precision (FP→0 requirement). |
| Analysis depth | **Intra-procedural (flow-sensitive) + method summaries + light ICC** | Catches the full OVAA cross-component flow while staying in challenge scope. Heavier levels (alias, full IFDS) documented as future work (§10). |
| Orchestration | **Temporal, docker-compose all-in** | Real workflow engine; Java SDK fits a Java engine; fan-out/fan-in demonstrates extensibility and the real value of an orchestrator. |
| Rules format | **External YAML, per-vulnerability-class**, FlowDroid-style method signatures | Satisfies "rules not hardcoded, abstract external format". |
| Output | **HTML + SARIF v2.1.0** | HTML for humans (challenge answer #6); SARIF for CI / VS Code / baseline comparison. |
| Reference tools | FlowDroid (architecture only, NOT reused), DroidBench (test fixtures), Opengrep (optional oracle/baseline) | FlowDroid is Soot/dex-bound; we borrow concepts, not code. |

---

## 3. Pipeline Architecture (6 independent apps + 1 orchestrator)

### 3.0 Core principle: independent, separately-runnable steps

Each step is its **own runnable application** — own `main`, own CLI, own build, own tests. A step reads its input **artifacts by path/uri** and writes its output artifact. Every step can be run **standalone** (feed it a fixture artifact for debugging or testing) *or* driven by the orchestrator. "Independent" means *separately launchable*, **not** dependency-free: a step legitimately consumes artifacts produced by earlier steps. The orchestrator holds **no analysis logic** — it only wires data flow, sequencing, parallelism, retries.

### 3.1 The six steps

| # | App | CLI (illustrative) | Input artifacts | Output artifact | Scheduling |
|---|-----|--------------------|-----------------|-----------------|------------|
| 1 | `decompiler` | `decompile --apk a.apk --out sources/` | `apk` | `sources/` + `AndroidManifest.xml` | sequential (first) |
| 2 | `parser` | `parse --src sources/ --out ast-index/` | `sources/` | `ast-index/` (serialized AST + symbols) | after 1, ∥ with 3 |
| 3 | `manifest-facts` | `mfacts --manifest AndroidManifest.xml --out facts.json` | `AndroidManifest.xml` | `facts.json` (exported, deeplinks, perms) | after 1, ∥ with 2 |
| 4 | `taint` | `taint --ast ast-index/ --facts facts.json --rule webview.yaml --out f.json` | `ast-index/` + `facts.json` + `rule.yaml` | `findings.json` | fan-out ×N rules |
| 5 | `manifest-misconfig` | `mscan --facts facts.json --rule misconfig.yaml --out f.json` | `facts.json` + `misconfig.yaml` | `findings.json` | fan-out |
| 6 | `reporter` | `report --findings 'f-*.json' --out report.html report.sarif` | all `findings*.json` | `report.html` + `report.sarif` | fan-in (last) |

`taint` (step 4) is a **single** application; the fan-out runs it multiple times with **different YAML rule files** (`webview.yaml`, `pathtraversal.yaml`). A new vulnerability class = a new YAML file — no code change.

### 3.2 Orchestrated DAG

```
                    ┌─────────────┐
                    │ decompiler  │  (1)
                    └──────┬──────┘
                  sources/ + AndroidManifest.xml
                     ┌─────┴─────┐
                     ▼           ▼
               ┌─────────┐  ┌──────────────┐
               │ parser  │  │manifest-facts│   (2 ∥ 3)
               └────┬────┘  └──────┬───────┘
                ast-index/      facts.json
                     └─────┬────────┴──────────────┐
                           ▼   fan-out (parallel)   ▼
        ┌──────────────┬──────────────┬────────────────────┐
        │ taint        │ taint        │ manifest-misconfig  │  (4 ×N, 5)
        │ webview.yaml │ pathtrav.yaml│ misconfig.yaml      │
        └──────┬───────┴──────┬───────┴─────────┬───────────┘
          findings-1     findings-2        findings-3
               └──────────────┼──────────────────┘
                              ▼  fan-in
                       ┌─────────────┐
                       │  reporter   │  (6)
                       └──────┬──────┘
                     report.html + report.sarif
```

**Why this shape:**
- **Independently runnable** — every step debugged/tested in isolation by supplying fixture artifacts; the orchestrator is just the production wiring.
- **Fan-out** = `Promise.allOf(activities)` in Temporal — true parallel workers, independent retry/timeout per branch.
- **Extensibility** — adding an analysis = one more entry in `analysisPlan`; the workflow code does not change.
- **One taint app, many YAML configs** = many vulnerability classes in parallel; directly demonstrates the "rules not hardcoded" requirement.
- `parser` and `manifest-facts` both depend only on `sources/`/`AndroidManifest.xml`, so they run in parallel; the fan-out waits on both.
- **Fan-in** `reporter` aggregates all findings — the real payoff of an orchestrator.

### 3.3 Runtime topology (docker-compose)

```
docker-compose:
  ├── temporal        (server)
  ├── temporal-ui     (workflow visibility)
  ├── postgres        (temporal persistence)
  ├── worker          (Java: hosts the 6 step apps as Temporal activities)
  └── minio           (S3-compatible artifact store; optional — shared volume fallback)
```

### 3.4 Manifest: facts vs analyzer (the dependency split)

Android manifest plays **two distinct roles**; conflating them breaks the parallelism:

1. **Manifest FACTS extraction** (`extractManifestFacts`) — extracts `exported` flags, `intent-filter`s, deeplink `scheme`/`host`, permissions → `manifest-facts.json`. This is **not** an analyzer; it produces no findings. The taint analyzer **depends** on it (entry-points + reachability), so it runs as a **sequential prerequisite** after decompile, before the fan-out.
2. **Manifest MISCONFIG analysis** (`manifestAnalyze`) — exported-without-permission, exported provider with `grantUriPermissions`, weak host validation, etc. as a genuine vulnerability class producing findings. This runs as **one analyzer in the parallel fan-out**, consuming the same facts.

So: facts extraction (step 3) is a prerequisite; misconfig analysis (step 5) is a parallel analyzer; taint (step 4) is a parallel analyzer that consumes facts.

### 3.5 Artifact store

`ArtifactStore` interface: `put(key, bytes)` / `get(key) -> bytes`.
- `LocalFsStore` — challenge default (shared volume / local dir).
- `S3Store` — cloud (MinIO locally; S3 in prod).

Every step reads its input artifact(s) by key and writes its output artifact by key. Steps are **idempotent**, so Temporal retries are free. This is the "each step is a worker producing an artifact consumed by the next" model, portable to cloud with no code change — each step app could run on its own worker/container.

### 3.6 Common analyzer contract (steps 4 & 5)

```
Analyzer.analyze(astIndexUri, factsUri, configUri) -> findingsUri
```

Both `taint` (4) and `manifest-misconfig` (5) implement this one contract, so the orchestrator treats fan-out branches uniformly — it just iterates `analysisPlan` and fans out. (The manifest analyzer ignores `astIndexUri`; the taint analyzer reads the pre-parsed `ast-index`.) `findings.json` is a shared schema (§7) so `reporter` (6) is analyzer-agnostic.

---

## 4. Components & Repo Layout (Java, Gradle multi-module)

Each step app is its own module producing both a **runnable CLI** (`main`) and a **library API** (so the Temporal worker can invoke it in-process). Shared types live in `common`; the orchestrator wires steps; `rules/` and `benchmark/` are non-code assets.

| Module | Kind | Responsibility |
|---|---|---|
| `apps/decompiler` | step 1 | jadx wrapper (`jadx-core` embedded or CLI): APK → `.java` sources + extracts raw `AndroidManifest.xml`. |
| `apps/parser` | step 2 | JavaParser + SymbolSolver over `sources/` → serialized `ast-index/` (parse-once), consumed by taint. |
| `apps/manifest-facts` | step 3 | Parse `AndroidManifest.xml` → `facts.json` (exported flags, intent-filters, deeplink scheme/host, permissions). No findings. |
| `apps/taint` | step 4 | The engine: rules loader, AST-index → per-method CFG, taint propagation, summaries, light ICC, reachability filter, findings. Config-driven: one engine, many YAML files. |
| `apps/manifest-misconfig` | step 5 | Manifest misconfiguration analyzer (exported-without-permission, weak host validation, provider grantUriPermissions, …), driven by `misconfig.yaml`. |
| `apps/reporter` | step 6 | Merge all `findings*.json` → HTML (template) + SARIF v2.1.0. |
| `orchestrator` | wiring | Temporal workflow + activities (one activity per step app), `analysisPlan` handling, fan-out/fan-in. No analysis logic. |
| `common` | lib | `ArtifactStore` (`LocalFsStore`/`S3Store`), `findings.json` schema, method-signature parser, shared model. |
| `rules/` | assets | External YAML rule files (NOT compiled in): `webview.yaml`, `pathtraversal.yaml`, `misconfig.yaml`. |
| `benchmark/` | assets | DroidBench harness (precision/recall) + OVAA fixture + optional Opengrep oracle. |

```
challenge/
├── apps/
│   ├── decompiler/           # step 1
│   ├── parser/               # step 2
│   ├── manifest-facts/       # step 3
│   ├── taint/                # step 4 (engine)
│   ├── manifest-misconfig/   # step 5
│   └── reporter/             # step 6
├── orchestrator/             # Temporal workflow + activities
├── common/                   # ArtifactStore, findings schema, signature parser
├── rules/                    # webview.yaml, pathtraversal.yaml, misconfig.yaml
├── benchmark/                # DroidBench harness, OVAA fixture, Opengrep oracle
├── docker-compose.yml        # temporal, ui, postgres, worker, minio
├── settings.gradle
└── docs/superpowers/specs/
```

Each `apps/<step>/` and `orchestrator/`, `common/`, `rules/`, `benchmark/` carries a `README.md` describing that step's purpose, exact input/output artifacts, CLI usage, and tests.

### 4.1 Implementation-plan coverage status

The design is covered by implementation plans in `docs/superpowers/plans/`:

| Area | Plan |
|---|---|
| Shared contracts and root build | `2026-06-27-common.md` |
| APK decompilation | `2026-06-27-decompiler.md` |
| Java source parsing / AST index | `2026-06-27-parser.md` |
| Manifest facts extraction | `2026-06-27-manifest-facts.md` |
| External rule assets | `2026-06-27-rules.md` |
| Taint/dataflow engine | `2026-06-27-taint.md` |
| Manifest misconfiguration analyzer | `2026-06-27-manifest-misconfig.md` |
| HTML/SARIF reporter | `2026-06-27-reporter.md` |
| Temporal orchestration and docker-compose runtime | `2026-06-27-orchestrator.md` |
| OVAA/DroidBench benchmark and E2E validation | `2026-06-27-benchmark.md` |

Recommended execution order: `common`, `decompiler`, `parser`, `manifest-facts`, `taint`, `manifest-misconfig`, `rules`, `reporter`, `orchestrator`, `benchmark`. Some plans can be implemented in parallel after `common`, but cross-plan validation tests will stay red until their dependencies exist.

---

## 5. External Rules Format (YAML, per-vulnerability-class)

```yaml
version: 1
rules:
  - id: ANDROID_WEBVIEW_INTENT_LOADURL
    vulnerability_class: webview-open-redirect
    severity: error
    cwe: CWE-601
    owasp_mobile: M1
    message: "Untrusted Intent/deeplink data flows into WebView.loadUrl"

    manifest_conditions:
      reachable_from_exported: true     # report only if source component is exported
                                        # OR reachable from an exported component via ICC

    sources:
      - signature: "android.content.Intent: java.lang.String getStringExtra(java.lang.String)"
      - signature: "android.content.Intent: android.net.Uri getData()"
      - signature: "android.net.Uri: java.lang.String getQueryParameter(java.lang.String)"

    sinks:
      - signature: "android.webkit.WebView: void loadUrl(java.lang.String)"
        tainted_args: [0]               # which parameter position is dangerous

    sanitizers:
      - signature: "android.webkit.URLUtil: boolean isHttpsUrl(java.lang.String)"
        # endsWith("example.com")-style checks are modeled as INCOMPLETE sanitizers (§6.6)

    propagators:                        # built-in defaults; rule may extend
      - "java.lang.String: java.lang.String concat(java.lang.String)"
      - "java.lang.StringBuilder: java.lang.StringBuilder append(java.lang.String)"
      - "android.net.Uri: android.net.Uri parse(java.lang.String)"
```

Second class, same engine, separate file `pathtraversal.yaml` (proves rules are config, not code):

```yaml
version: 1
rules:
  - id: ANDROID_PATH_TRAVERSAL_PROVIDER
    vulnerability_class: path-traversal
    severity: error
    cwe: CWE-22
    owasp_mobile: M8
    message: "Untrusted Uri path segment flows into file open (path traversal)"
    manifest_conditions:
      reachable_from_exported: true     # exported ContentProvider authority
    sources:
      - signature: "android.net.Uri: java.lang.String getLastPathSegment()"
      - signature: "android.net.Uri: java.util.List getPathSegments()"
    sinks:
      - signature: "java.io.File: void <init>(java.io.File,java.lang.String)"
        tainted_args: [1]
      - signature: "android.os.ParcelFileDescriptor: android.os.ParcelFileDescriptor open(java.io.File,int)"
        tainted_args: [0]
    sanitizers:
      - signature: "android.text.TextUtils: boolean isEmpty(java.lang.CharSequence)"
        # canonical-path / "../" checks modeled as sanitizers when present
```

This maps to OVAA's `TheftOverwriteProvider.openFile` (`getLastPathSegment()` → `new File(...)` → `ParcelFileDescriptor.open`).

**Signature grammar** (FlowDroid/Soot-style, easy to parse and to match against SymbolSolver output):
`<fully.qualified.Class: ReturnType methodName(ParamType,ParamType,...)>` — inner classes use `$`.

**Why this shape:** method-signature granularity (simpler than AST patterns, sufficient for Android), grouped per vulnerability class (maintainable), first-class Android `manifest_conditions` (unique to the Android threat model), carries CWE/OWASP/severity metadata. The taint engine is fully policy-agnostic — all detection logic lives in YAML.

A separate `misconfig.yaml` drives the manifest analyzer (different rule kind, same external-YAML principle).

---

## 6. Taint Analysis Algorithm

### 6.1 Parse (the `parseSources` prerequisite)
JavaParser + JavaSymbolSolver over `sources/`, run **once** by the `parseSources` step into the `ast-index` artifact. SymbolSolver configured `--noclasspath`-style fail-soft: unresolved types raise catchable exceptions; analysis continues, resolving the calls it can (`Intent.getStringExtra`, `WebView.loadUrl`). Every taint analyzer in the fan-out loads `ast-index` rather than re-parsing.

### 6.2 Source / sink matching
Walk `MethodCallExpr` nodes; resolve each to a signature; match against the rule's `sources`/`sinks`. Receiver type is checked via SymbolSolver to avoid look-alike false matches.

### 6.3 Intra-procedural, flow-sensitive propagation
- Build a per-method CFG (linearize statements; handle if/while/for/switch/try successor edges).
- Worklist fixpoint over the CFG. State = set of tainted variables / shallow access paths (`v`, `v.f`).
- A source call taints its LHS variable.
- Assignment / expression `b = f(a, ...)` propagates taint from operands to `b`.
- Reassignment to a clean value **kills** taint (flow-sensitivity): `x = secret; x = "safe"; sink(x)` is **not** a leak.
- Tainted value reaching a sink's `tainted_args` position → candidate finding.

### 6.4 Method summaries (light inter-procedural)
Per user method, compute a summary: *"return tainted if param i tainted"* and *"param i becomes tainted (out-param)"*. Apply at call sites for crude context-sensitivity without IFDS. Fixpoint across summaries; cap recursion depth.

### 6.5 Light ICC (the Android-specific core)
On `startActivity(intent)` / `startService(...)` where the intent carries `putExtra(K, tainted)`:
- Resolve the target component (`new Intent(ctx, X.class)`, or action string matched against manifest facts).
- Mark the target component's `getXExtra(K)` reads (matching key `K`) as **sources**, propagating the cross-component taint.

This is what connects OVAA's `DeeplinkActivity` (`putExtra("url", tainted)` + `startActivity`) to `WebViewActivity` (`getStringExtra("url")` → `loadUrl`).

### 6.6 Sanitizers (incl. incomplete)
- A sanitizer call on a tainted value kills taint.
- OVAA's `host.endsWith("example.com")` is modeled as an **incomplete sanitizer**: the flow is still reported (it is bypassable, e.g. `evilexample.com`), but the finding is annotated `incomplete-sanitizer` so the report explains the residual risk rather than silently dropping or silently flagging.

### 6.7 Reachability filter (FP → 0)
A candidate finding is emitted **only if** its source component is, per `manifest-facts.json`, **exported** OR **reachable from an exported component via ICC**. A flow inside a non-exported, unreachable component is suppressed. This directly serves the challenge's "FP rate → 0" requirement.

---

## 7. Findings Schema & Output

### 7.1 `findings.json` (shared, analyzer-agnostic)
```json
{
  "analyzer": "taint-engine",
  "ruleId": "ANDROID_WEBVIEW_INTENT_LOADURL",
  "findings": [{
    "ruleId": "ANDROID_WEBVIEW_INTENT_LOADURL",
    "severity": "error",
    "message": "Untrusted deeplink data flows into WebView.loadUrl",
    "flow": [
      {"file": "...DeeplinkActivity.java", "line": 47, "label": "source: Uri.getQueryParameter(\"url\")"},
      {"file": "...DeeplinkActivity.java", "line": 51, "label": "putExtra(\"url\", url) + startActivity"},
      {"file": "...WebViewActivity.java",  "line": 20, "label": "getStringExtra(\"url\")"},
      {"file": "...WebViewActivity.java",  "line": 20, "label": "sink: WebView.loadUrl(url)"}
    ],
    "notes": ["incomplete-sanitizer: host.endsWith(\"example.com\") bypassable", "entry component exported via deeplink oversecured://ovaa"]
  }]
}
```

### 7.2 HTML report
List of findings with severity; source→sink path rendered as ordered steps with code snippets, file paths, and line numbers; manifest context (exported / deeplink scheme+host); incomplete-sanitizer annotations. Generated from `findings.json` (merged across analyzers).

### 7.3 SARIF v2.1.0
`runs[].results[]` with `ruleId`, `level`, `message`, `locations` (sink), and `codeFlows[].threadFlows[].locations[]` = the ordered source→sink taint path. Consumable by GitHub code scanning / VS Code SARIF viewer, and for baseline comparison with Opengrep. Generated from the same merged findings.

---

## 8. Test Fixtures & Validation

- **DroidBench harness** — run the engine over selected categories and score against ground truth (`@number_of_leaks` JavaDoc + `// source` / `// sink, leak` comments) → TP / FP / FN → precision / recall / F1.
  - In-scope categories (realistic to pass): `GeneralJava`, `Lifecycle` / `Callbacks` (with an entry-point model), simple `FieldAndObjectSensitivity`, and ICC/WebView-relevant cases where applicable.
  - Out-of-scope (documented): `Reflection(_ICC)`, `ImplicitFlows`, `InterComponent/InterAppCommunication` (beyond light ICC key-matching), `DynamicLoading`, `Native`, `Threading`, `EmulatorDetection`.
- **OVAA** — end-to-end: build `ovaa.apk` (no prebuilt release; `./gradlew assembleDebug`) and run the full pipeline with both taint configs. Expect exactly **2** taint findings — deeplink → `WebView.loadUrl` (`webview.yaml`) and Uri path segment → `ParcelFileDescriptor.open` (`pathtraversal.yaml`) — plus any manifest-misconfig findings, and **0** false positives.
- **Opengrep oracle (optional)** — run a Semgrep-style ruleset side-by-side as an independent baseline; show our detections match a battle-tested tool.
- **Unit tests (TDD)** — each engine block (CFG, intra propagation, summaries, ICC, sanitizers, reachability, rules loader, SARIF/HTML emit).

---

## 9. Reference Tools (positioning)

- **FlowDroid** — reference architecture only. Built on Soot/Jimple + IFDS + alias analysis + dummy-main; Soot is dex/bytecode-bound and its Java-source frontend is abandoned (Java-7-capped). We borrow the source/sink-list concept and the forward-taint idea; we do **not** reuse the code.
- **DroidBench** — ground-truth micro-benchmark APKs; our precision/recall harness.
- **Opengrep / Semgrep** — battle-tested taint engine with external YAML rules. Wrapping it would **not** satisfy "implement a taint analysis" (engine is someone else's), so it is used only as an optional **baseline oracle**.

---

## 10. Limitations & Future Work

**Chosen depth:** intra-procedural (flow-sensitive) + method summaries + light ICC (Intent-extra key matching). This was a deliberate scope choice to catch the OVAA flow end-to-end while remaining implementable and demoable within the challenge.

**Known unsoundness / not covered (and how to extend):**
- **Aliasing / points-to** — two references to the same heap object are not reconciled. Extend with an on-demand backward alias pass (FlowDroid/Andromeda-style).
- **Full context-sensitivity** — summaries are an approximation of IFDS valid call/return matching. Extend by adopting an IFDS/IDE solver (Heros).
- **Full ICC / inter-app** — only Intent-extra key matching with resolvable targets; no Intent resolution via `Epicc`/implicit-intent matching across all components. Extend toward IccTA/Amandroid-style ICC.
- **Reflection, implicit (control-dependency) flows, native (JNI), dynamic class loading** — out of scope; each requires dedicated machinery.
- **Decompiler fidelity** — analyzing jadx output (an approximation of bytecode) is less sound than analyzing dex directly; jadx may fail or mangle lambdas/coroutines/synthetics. Mitigated by JavaParser's fail-soft parsing; documented as a known tradeoff.
- **Field-sensitivity** — shallow access paths only (`v`, `v.f`), no k-bounded deep paths.

These mirror how the real tools frame their precision/recall tradeoffs; they are explicit, not accidental.
