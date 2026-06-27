# `test-subjects` — analysis inputs

Test targets for the pipeline. Sourced from [DroidBench](https://github.com/secure-software-engineering/DroidBench) and [OVAA](https://github.com/oversecured/ovaa).

## Layout
| Dir | Contents | Used by |
|-----|----------|---------|
| `apk/droidbench/` | 188 prebuilt DroidBench APKs (by category) | step 1 `decompiler` (input) |
| `source/droidbench/` | DroidBench `projects/` source (313 `.java`) — ground truth: `@number_of_leaks` JavaDoc + `// source` / `// sink, leak` comments | benchmark scoring; taint reference |
| `source/ovaa/` | OVAA app source (20 `.java`, Gradle project) | taint input; build `ovaa.apk` via `./gradlew assembleDebug` |
| `decompiled/` | empty — populated by `decompiler` output (jadx) | step 4 `taint` (input) |

## Flow
- **Decompiler path:** `apk/droidbench/*.apk` → `decompiler` → `decompiled/`.
- **Taint path:** decompiled DroidBench + OVAA source → `parser` → `taint`.

OVAA has no prebuilt release; build the APK from `source/ovaa/` when needed. DroidBench APKs are shipped prebuilt, so they feed the decompiler directly.

See spec §8 (validation) and the [benchmark](../benchmark) module.
