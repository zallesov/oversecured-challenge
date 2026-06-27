# Step 1 — `decompiler`

Decompiles an Android APK into readable Java source for downstream analysis.

Part of the [Android Taint SAST Pipeline](../../docs/superpowers/specs/2026-06-27-android-taint-sast-design.md). Runs **first**, sequentially. Independently runnable: give it an APK, get a sources tree back.

## What it does
Wraps **jadx** (`jadx-core` embedded, or the `jadx` CLI) to turn `classes.dex` into `.java` files, and extracts the decoded `AndroidManifest.xml`. We analyze decompiled source (not dex/Jimple) because it is closest to what a developer reads and is hand-traceable for the report.

## Input artifacts
| Name | Type | Description |
|------|------|-------------|
| `--apk` | file | The Android APK to analyze (e.g. `ovaa.apk`, a DroidBench case). |

## Output artifacts
| Name | Type | Description |
|------|------|-------------|
| `sources/` | dir | Decompiled `.java` tree (package directories). |
| `sources/AndroidManifest.xml` | file | Decoded manifest, consumed by step 3 (`manifest-facts`). |

## CLI (illustrative)
```
decompile --apk app.apk --out sources/
```

## Consumed by
- Step 2 `parser` (reads `sources/`)
- Step 3 `manifest-facts` (reads `sources/AndroidManifest.xml`)

## Tests
- Decompile a tiny fixture APK → assert expected `.java` files and a decoded manifest exist.
- Corrupt/empty APK → graceful, non-zero exit with a clear error.
- Manifest extraction present even when some classes fail to decompile (jadx is best-effort).

## Notes / limitations
jadx output is an approximation of the bytecode; it may fail or mangle lambdas, Kotlin coroutines, and synthetics. The downstream parser (step 2) is configured fail-soft to tolerate this. See spec §10.
