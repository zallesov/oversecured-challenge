# Android Taint SAST Pipeline

A SAST pipeline that takes an Android **APK**, decompiles it, runs a **taint / dataflow analysis** driven entirely by **external YAML rules**, and emits an **HTML** + **SARIF** report. Built for the OverSecured Coding Challenge (Part 2).

**Primary vulnerability class:** Intent / deeplink data → `WebView.loadUrl` (open redirect / XSS).

Full design: [`docs/superpowers/specs/2026-06-27-android-taint-sast-design.md`](docs/superpowers/specs/2026-06-27-android-taint-sast-design.md).

## Pipeline (6 independent apps + 1 orchestrator)

```
decompiler → { parser ∥ manifest-facts } → fan-out{ taint×rules, manifest-misconfig } → reporter → ai-triage
```

Each step is its own runnable app (own CLI + tests), reading artifacts from earlier steps and writing one artifact. The orchestrator (Temporal) only wires them.

| Step | Module | Role |
|------|--------|------|
| 1 | [`apps/decompiler`](apps/decompiler) | APK → decompiled Java + manifest |
| 2 | [`apps/parser`](apps/parser) | Java → AST + symbol index (parse-once) |
| 3 | [`apps/manifest-facts`](apps/manifest-facts) | manifest → attack-surface facts |
| 4 | [`apps/taint`](apps/taint) | the config-driven taint engine |
| 5 | [`apps/manifest-misconfig`](apps/manifest-misconfig) | manifest misconfiguration findings |
| 6 | [`apps/reporter`](apps/reporter) | merge findings → HTML + SARIF |
| 7 | [`apps/ai-triage`](apps/ai-triage) | AI per-finding triage sidecar (verdict + fix) |
| — | [`orchestrator`](orchestrator) | Temporal workflow (wiring only) |
| — | [`common`](common) | ArtifactStore, findings schema, signature parser |
| — | [`rules`](rules) | external YAML detection rules |
| — | [`benchmark`](benchmark) | DroidBench + OVAA validation |

### AI Triage (sidecar)

After the report is built, an AI triage step (`apps/ai-triage`) reads the SARIF
report and decompiled sources in a LangChain4j tool-calling loop and writes
`ai-triage.json` + `ai-triage.md` with a per-finding verdict
(`exploitable` / `needs-review` / `safe`), re-judged severity, and a concrete
fix suggestion.

It is always-on and fail-soft: with no API key or on any error it writes an
empty sidecar and the pipeline still succeeds.

Configure via environment variables:

- `OPENROUTER_API_KEY` — OpenRouter API key (required to actually run the agent).
- `OPENROUTER_MODEL` — model id (default `anthropic/claude-3.5-sonnet`).

## Status
Design approved; implementation pending (see spec + per-module READMEs).
