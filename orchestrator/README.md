# `orchestrator` — Temporal pipeline wiring

Drives the six step apps as a Temporal workflow. **Holds no analysis logic** — only sequencing, parallelism, retries, and artifact hand-off.

Part of the [Android Taint SAST Pipeline](../docs/superpowers/specs/2026-06-27-android-taint-sast-design.md).

## What it does
Defines `AnalyzeApkWorkflow(apkUri, analysisPlan)` and one Temporal **activity per step app** (invoking each app's library entrypoint in the worker). It executes the DAG:

```
decompiler → { parser ∥ manifest-facts } → fan-out{ taint×N rules, manifest-misconfig } → reporter
```

- **Fan-out** = `Promise.allOf(...)` — true parallel activities, independent retry/timeout per branch.
- **`analysisPlan`** = the list of fan-out configs (which rule files, which analyzers). Adding an analysis = one more entry; the workflow code does not change.
- **Artifact hand-off** via `common`'s `ArtifactStore` — each activity gets input uris, writes an output uri.

## Input
| Name | Description |
|------|-------------|
| `apkUri` | The APK artifact to analyze. |
| `analysisPlan` | Fan-out config: rule files + analyzers to run. |

## Output
| Name | Description |
|------|-------------|
| `report.html`, `report.sarif` | Final artifacts from step 6. |

## Runtime (docker-compose)
`temporal` (server), `temporal-ui`, `postgres`, `worker` (hosts the 6 step apps), `minio` (optional S3-compatible artifact store; shared-volume fallback otherwise).

## Tests
- Workflow unit test with mocked activities → asserts DAG order, fan-out cardinality, fan-in.
- A failing activity → retried per policy; permanent failure surfaces cleanly.
- `analysisPlan` with N taint rules → N parallel branches, all reach the reporter.

## Notes
This is where Temporal earns its keep: parallel fan-out, per-branch retries, and an extensible plan. Each step app remains independently runnable outside Temporal. See spec §3.
