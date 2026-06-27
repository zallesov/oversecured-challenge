# Step 6 — `reporter`

Aggregates all findings into human- and machine-readable reports (fan-in).

Part of the [Android Taint SAST Pipeline](../../docs/superpowers/specs/2026-06-27-android-taint-sast-design.md). Runs **last**, after the fan-out completes. Independently runnable: give it a set of `findings*.json` files, get reports.

## What it does
Merges every analyzer's `findings.json` (taint branches + manifest-misconfig) and renders:
- **HTML** — the primary, human-readable report: findings by severity, the source→sink path as ordered steps with code snippets / file:line, manifest context (exported / deeplink scheme+host), and incomplete-sanitizer annotations.
- **SARIF v2.1.0** — machine-readable; `results[]` with `codeFlows[].threadFlows[]` carrying the ordered taint path. Consumable by GitHub code scanning / VS Code SARIF viewer and for baseline comparison with Opengrep.

Both outputs are generated from the same merged finding objects, so they never diverge. The reporter is **analyzer-agnostic** — it only depends on the shared `findings.json` schema.

## Input artifacts
| Name | Type | Description |
|------|------|-------------|
| `--findings` | glob/files | All `findings*.json` from the fan-out (steps 4 & 5). |

## Output artifacts
| Name | Type | Description |
|------|------|-------------|
| `report.html` | file | Human-readable report. |
| `report.sarif` | file | SARIF v2.1.0 JSON. |

## CLI (illustrative)
```
report --findings 'findings-*.json' --out report.html report.sarif
```

## Tests
- Merge multiple findings files → counts and ordering correct, no duplicates.
- HTML renders the full source→sink path with file:line and incomplete-sanitizer note.
- SARIF validates against the v2.1.0 schema; `threadFlows` step order matches the finding's flow.
- Empty input → valid empty report (no crash).

## Notes
HTML is the deliverable the challenge asks for; SARIF is the bonus interchange/CI format. See spec §7.
