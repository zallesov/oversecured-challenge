# Step 3 — `manifest-facts`

Extracts attack-surface facts from `AndroidManifest.xml`. **Fact extraction, not an analyzer** — it produces no findings.

Part of the [Android Taint SAST Pipeline](../../docs/superpowers/specs/2026-06-27-android-taint-sast-design.md). Runs after step 1, **in parallel** with step 2 (`parser`). Independently runnable.

## What it does
Parses the decoded manifest into structured `facts.json`: which components are `exported`, their `intent-filter`s, deeplink `scheme`/`host`, and declared permissions. These facts drive two things downstream:
1. **Entry-point identification** — where untrusted data can enter (exported components, browsable deeplinks). Android has no `main`; the manifest defines the real entry points.
2. **Reachability filter** — the taint analyzer reports a flow only if its source component is exported or reachable from an exported one (false-positive reduction).

## Input artifacts
| Name | Type | Description |
|------|------|-------------|
| `--manifest` | file | `AndroidManifest.xml` from step 1. |

## Output artifacts
| Name | Type | Description |
|------|------|-------------|
| `facts.json` | file | Components with `exported`, intent-filters, deeplink scheme/host, permissions. |

## CLI (illustrative)
```
mfacts --manifest sources/AndroidManifest.xml --out facts.json
```

## Consumed by
- Step 4 `taint` (reachability + entry-points)
- Step 5 `manifest-misconfig` (its analysis input)

## Tests
- OVAA manifest fixture → assert `DeeplinkActivity` exported with deeplink `oversecured://ovaa`, `WebViewActivity` not exported, provider authorities captured.
- Implicit-vs-explicit `exported` defaults handled per Android rules (e.g. component with an intent-filter defaults exported on older targetSdk).
- Manifest with no exported components → valid, empty-surface `facts.json`.

## Logging — emoji registry
Per the [logging conventions](../../docs/superpowers/reference/2026-06-27-logging.md), each boundary function owns one function emoji:

| Boundary function | Emoji |
|-------------------|-------|
| `ManifestFactsCommand.call` | 🧭 |
| `ManifestFactsApp.extract` | 📜 |

## Notes
This is the dependency that keeps the fan-out honest: taint depends on these facts, so this step is a **prerequisite**, not a fan-out analyzer. See spec §3.4.
