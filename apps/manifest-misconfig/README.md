# Step 5 — `manifest-misconfig`

Manifest **misconfiguration analyzer** — a genuine analyzer that produces findings (distinct from step 3, which only extracts facts).

Part of the [Android Taint SAST Pipeline](../../docs/superpowers/specs/2026-06-27-android-taint-sast-design.md). Runs in the **parallel fan-out** alongside `taint`. Independently runnable.

## What it does
Consumes `facts.json` and, driven by external `misconfig.yaml`, flags manifest-level weaknesses that need no dataflow — for example:
- components `exported` without a protecting (signature) permission,
- a `ContentProvider` exported with `grantUriPermissions=true`,
- browsable deeplink components with weak host validation,
- over-broad `FileProvider` paths.

Same external-YAML principle as the taint engine, different rule kind. Implements the shared analyzer contract (§3.6), so the orchestrator schedules it identically to a taint branch.

## Input artifacts
| Name | Type | Description |
|------|------|-------------|
| `--facts` | file | `facts.json` from step 3. |
| `--rule` | file | `misconfig.yaml` (external rules). |

## Output artifacts
| Name | Type | Description |
|------|------|-------------|
| `findings.json` | file | Shared findings schema (same shape as the taint output). |

## CLI (illustrative)
```
mscan --facts facts.json --rule rules/misconfig.yaml --out findings-misconfig.json
```

## Consumed by
- Step 6 `reporter`

## Tests
- OVAA facts → flags exported components / provider grantUriPermissions per rules.
- A hardened manifest (nothing exported, permissions in place) → zero findings.
- Rule toggling: disabling a rule in YAML removes only its findings (proves config-driven).

## Notes
Why a separate analyzer and not folded into taint: it is config-only (no source→sink flow), but it shares the manifest facts and the findings schema, so it slots cleanly into the fan-out. See spec §3.4.
