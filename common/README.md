# `common` — shared library

Cross-cutting types shared by every step app and the orchestrator. No analysis logic of its own.

Part of the [Android Taint SAST Pipeline](../docs/superpowers/specs/2026-06-27-android-taint-sast-design.md).

## Contents
- **`ArtifactStore`** — `put(key, bytes)` / `get(key) -> bytes`. Implementations:
  - `LocalFsStore` — challenge default (shared volume / local dir).
  - `S3Store` — cloud (MinIO locally, S3 in prod).
  Steps receive uris/paths and never assume physical location → portable to separate cloud workers with no code change.
- **`findings.json` schema** — the shared finding model (rule id, severity, message, ordered source→sink `flow` steps with file:line, `notes`). Produced by steps 4 & 5, consumed by step 6. Keeping it here makes the reporter analyzer-agnostic.
- **Method-signature parser** — parses FlowDroid/Soot-style `<fqcn: ret method(params)>` signatures used in rule files; matches them against resolved AST symbols.
- Shared model/util (artifact keys, severity enum, etc.).

## Why a shared module
The stable contracts between steps (`findings.json`, artifact keys, signature grammar) live in one place so each boundary is a single, testable definition and steps can evolve independently behind it.

## Tests
- `LocalFsStore` round-trip; `S3Store` against MinIO.
- `findings.json` (de)serialization round-trip; schema validation.
- Signature parser: valid/invalid signatures, inner-class `$` handling, param-type lists.

## Notes
See spec §3.5 (artifact store), §3.6 (analyzer contract), §5 (signature grammar), §7 (findings schema).
