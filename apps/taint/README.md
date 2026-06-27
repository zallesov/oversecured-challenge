# Step 4 — `taint` (the engine)

Config-driven taint / dataflow analyzer. **One engine, many YAML rule files** — this is the heart of the challenge.

Part of the [Android Taint SAST Pipeline](../../docs/superpowers/specs/2026-06-27-android-taint-sast-design.md). Runs in the **parallel fan-out**, once per rule file. Independently runnable.

## What it does
Loads an external YAML rule (sources / sinks / sanitizers / manifest conditions), then over the pre-parsed `ast-index`:
1. **Source/sink matching** against resolved method signatures (receiver type checked via SymbolSolver).
2. **Intra-procedural, flow-sensitive** propagation over a per-method CFG (worklist fixpoint; reassignment to a clean value kills taint).
3. **Method summaries** for light inter-procedural flow (return-taint / out-param-taint), capped recursion.
4. **Light ICC** — `putExtra(K, tainted)` + `startActivity` linked to the target component's `getXExtra(K)` (this connects OVAA's deeplink hop).
5. **Sanitizers** kill taint; bypassable checks (`endsWith("example.com")`) are modeled as *incomplete sanitizers* — still reported, annotated.
6. **Reachability filter** — emit only if the source component is exported / reachable, per `facts.json` (FP → 0).

Detection logic is **100% in YAML**; the engine is policy-agnostic. New vulnerability class = new rule file.

## Input artifacts
| Name | Type | Description |
|------|------|-------------|
| `--ast` | dir | `ast-index/` from step 2. |
| `--facts` | file | `facts.json` from step 3 (reachability + ICC targets). |
| `--rule` | file | One external YAML rule (e.g. `rules/webview.yaml`). |

## Output artifacts
| Name | Type | Description |
|------|------|-------------|
| `findings.json` | file | Shared findings schema (rule id, severity, source→sink flow steps, notes). |

## CLI (illustrative)
```
taint --ast ast-index/ --facts facts.json --rule rules/webview.yaml --out findings-webview.json
```

## Consumed by
- Step 6 `reporter`

## Tests (TDD, per block)
- **Rules loader** — parse YAML, validate signature grammar.
- **CFG** — branch/loop/try successor edges.
- **Intra propagation** — positive flow; flow-sensitivity kill (`x=secret; x="safe"; sink(x)` → no leak).
- **Summaries** — return-taint / out-param-taint across a call.
- **ICC** — putExtra/getStringExtra key matching across components.
- **Sanitizers** — full sanitizer kills; incomplete sanitizer still reports + annotates.
- **Reachability** — flow in a non-exported unreachable component suppressed.
- **End-to-end** — OVAA `webview.yaml` → exactly 1 finding; `pathtraversal.yaml` → exactly 1 finding.

## Notes / limitations
Depth = intra + summaries + light ICC by design. No aliasing, full IFDS context-sensitivity, reflection, implicit flows, native, or dynamic loading. See spec §10.
