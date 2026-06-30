# Task 2 Report — PocketBase Collections Schema (Migration)

## PocketBase Version Targeted

**v0.28.x** (image `ghcr.io/muchobien/pocketbase:0.28.x`).
API confirmed via Context7 against the `/pocketbase/pocketbase/v0.28.4` and `/websites/pocketbase_io` sources.

## Migration File

`ui/pb_migrations/1700000000_init_collections.js`

## Migration API Used

`migrate((app) => { ... }, (app) => { ... })` with:
- `new Collection({ type, name, listRule, viewRule, createRule, updateRule, deleteRule, fields, indexes })`
- `app.save(collection)` to persist
- `app.findCollectionByNameOrId(name)` to resolve cross-collection IDs at migration time
- Field definitions as flat objects `{ type, name, required, maxSelect, collectionId, cascadeDelete, ... }`
- Indexes as raw SQL strings in the `indexes` array

## Collections Created

### `users` (auth)
PocketBase's built-in auth collection. **Not created by this migration** — it exists by default. No extra fields added. Default self-registration create rule left intact. Migration references it by name to resolve `collectionId` for `runs.user`.

### `runs` (base)
| Field | Type | Required | Notes |
|-------|------|----------|-------|
| user | relation→users | yes | maxSelect 1, cascadeDelete true |
| workflowId | text | yes | unique index |
| apkFilename | text | yes | |
| apkSha256 | text | no | |
| apkSizeBytes | number | no | |
| artifactRoot | text | yes | |
| status | text | yes | |
| message | text | no | |
| startedAt | date | no | |
| finishedAt | date | no | |
| durationMs | number | no | |
| reportHtmlKey | text | no | |
| reportSarifKey | text | no | |

**API rules:** `listRule = viewRule = "user = @request.auth.id"`. `createRule = updateRule = deleteRule = null` (superuser bypass).
**Indexes:** `CREATE UNIQUE INDEX idx_runs_workflowId ON runs (workflowId)`, `CREATE INDEX idx_runs_user ON runs (user)`.

### `run_nodes` (base)
| Field | Type | Required | Notes |
|-------|------|----------|-------|
| run | relation→runs | yes | maxSelect 1, cascadeDelete true |
| nodeId | text | yes | |
| label | text | no | |
| kind | text | no | |
| state | text | yes | |
| message | text | no | |
| queuedAt | date | no | |
| startedAt | date | no | |
| finishedAt | date | no | |
| durationMs | number | no | |
| findingCount | number | no | |
| severityCounts | json | no | |
| metrics | json | no | |
| diagnostics | json | no | |
| artifacts | json | no | |
| error | json | no | |
| findingsKeys | json | no | |
| findingsIngested | bool | no | |

**API rules:** `listRule = viewRule = "run.user = @request.auth.id"`. create/update/delete = null.
**Index:** `CREATE UNIQUE INDEX idx_run_nodes_run_nodeId ON run_nodes (run, nodeId)` (mirrors old composite PK).

### `findings` (base)
| Field | Type | Required | Notes |
|-------|------|----------|-------|
| run | relation→runs | yes | maxSelect 1, cascadeDelete true |
| nodeId | text | no | plain text (not a relation) |
| analyzer | text | yes | |
| ruleId | text | no | |
| vulnerabilityClass | text | no | |
| severity | text | yes | |
| message | text | yes | |
| cwe | text | no | |
| owaspMobile | text | no | |
| sourceFile | text | no | |
| sourceLine | number | no | |
| sinkFile | text | no | |
| sinkLine | number | no | |
| rawJson | json | no | carries AI-triage verdict/confidence/fix |

**API rules:** `listRule = viewRule = "run.user = @request.auth.id"`. create/update/delete = null.
**Index:** `CREATE INDEX idx_findings_run ON findings (run)`.

## API Syntax Uncertainties / Concerns

1. **`collectionId` resolution at migration time:** The migration calls `app.findCollectionByNameOrId("users")` and `app.findCollectionByNameOrId("runs")` to resolve the `collectionId` for relation fields. This is the documented pattern for JS migrations that need cross-collection references. `users` must exist before `runs` is created (it does — it is PocketBase's built-in), and `runs` must be saved before `run_nodes`/`findings` are created (the migration saves them in order).

2. **`null` rules = superuser-only:** Setting `createRule: null`, `updateRule: null`, `deleteRule: null` in PB means only the superuser/admin API token can write. Browser clients with auth tokens cannot write. This matches the spec (backend uses superuser client).

3. **`bool` field type name:** In the PB v0.28.x flat-field API, the boolean type is `"bool"`. This is consistent with the docs but was not shown in a live example for JSVM — confirmed from the field-type enumeration in the source migration code (`case "bool": field = toBoolField(field)`).

4. **No `down` migration tested:** Cannot validate at migration time without a running PB instance. The down migration drops collections in reverse dependency order (findings → run_nodes → runs) with try/catch for idempotency.

5. **Index column names for relation fields:** PocketBase stores relation field values as the related record's ID string in a column named after the field (e.g., `run`, `user`). Index SQL therefore uses the field name directly, not `run_id` or `user_id`.
