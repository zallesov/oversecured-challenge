# Step 2 — `parser`

Parses the decompiled Java once into a reusable AST + symbol index (parse-once).

Part of the [Android Taint SAST Pipeline](../../docs/superpowers/specs/2026-06-27-android-taint-sast-design.md). Runs after step 1, **in parallel** with step 3 (`manifest-facts`). Independently runnable.

## What it does
Runs **JavaParser + JavaSymbolSolver** over `sources/` and serializes the result into an `ast-index/` artifact. Symbol resolution is configured fail-soft (`--noclasspath`-style): unresolved types raise catchable exceptions and parsing continues, still resolving the calls we care about (`Intent.getStringExtra`, `WebView.loadUrl`). Parsing once here means every taint fan-out branch consumes the index instead of re-parsing.

## Input artifacts
| Name | Type | Description |
|------|------|-------------|
| `--src` | dir | `sources/` produced by step 1. |

## Output artifacts
| Name | Type | Description |
|------|------|-------------|
| `ast-index/` | dir | Serialized AST + resolved-symbol index (per compilation unit). |

## CLI (illustrative)
```
parse --src sources/ --out ast-index/
```

## Consumed by
- Step 4 `taint` (reads `ast-index/`)

## Tests
- Parse a fixture source tree → assert the index round-trips and exposes expected method-call nodes with resolved signatures.
- Source with unresolvable types → parse still succeeds; affected calls flagged unresolved, not fatal.
- Syntactically broken decompiled file → isolated to that compilation unit, rest of the index intact.

## Notes / limitations
Symbol resolution depends on what jadx emitted; some receiver types may stay unresolved. Taint matching (step 4) falls back to heuristic receiver-type checks in those cases. See spec §6.1.
