# Server Docker Stack — Design

**Date:** 2026-06-28
**Status:** Approved for planning

## Goal

Provide a single, self-contained Docker Compose stack to deploy the whole Android SAST
system on the server. The stack runs Temporal, the analysis pipeline (worker, with a
baked-in `android.jar`), the UI (frontend + backend bridge), and Pocketbase as the UI's
backend datastore + auth. A second, unrelated stack already runs Pocketbase on the same
server, so this stack must not interfere: all published host ports are offset into the
`18xxx` range and the compose project is isolated by name.

## Non-Goals

- Pocketbase collection schema, `pb_hooks`, and the UI's `db.ts`/`auth.ts` port from
  Postgres/JWT → Pocketbase. The UI is built by another agent; this stack only provisions
  Pocketbase and exposes the contract (env + shared volume).
- TLS / reverse proxy / public DNS. Out of scope; assume an external proxy terminates TLS.
- Changing the existing dev `docker-compose.yml`. It stays as-is.

## Decisions (from brainstorming)

| Question | Decision |
|---|---|
| UI source | Keep in-tree `ui/`; no subtree yet. Provide a ready `git subtree add` command for later. |
| Pocketbase role | Backend datastore + auth, replacing the dev `ui-postgres`. UI's Express server stays as the Temporal bridge. |
| android.jar | Baked into the worker image at build time. No host Android SDK mount. |
| Port isolation | All published ports offset to `18xxx`. Distinct compose project name. |
| PB→Temporal bridge | The UI backend (existing TS Express server) is the bridge — per `docs/superpowers/plans/2026-06-28-ui-run-status-graph.md`. |
| Pocketbase image | `ghcr.io/muchobien/pocketbase` (community image, pinned tag). |
| Compose file | New `docker-compose.server.yml`; dev compose untouched. |
| Temporal gRPC exposure | Internal only. Only the Temporal **UI** is published. |

## Architecture

Six services on one private compose network (`oversecured` project):

| Service | Image / Build | Host port | Internal | Volumes |
|---|---|---|---|---|
| `temporal-postgres` | `postgres:16` | none | 5432 | `temporal-postgres` |
| `temporal` | `temporalio/auto-setup:1.29.6` | none (internal only) | 7233 | — |
| `temporal-ui` | `temporalio/ui:2.51.0` | `18080` → 8080 | 8080 | — |
| `pocketbase` | `ghcr.io/muchobien/pocketbase:<pinned>` | `18090` → 8090 | 8090 | `pb-data` |
| `worker` (pipeline) | build `orchestrator/Dockerfile` + baked `android.jar` | none (private) | — | `artifacts` (rw), `./rules` (ro), `./test-subjects` (ro) |
| `ui` (frontend + backend bridge) | build `ui/Dockerfile` | `18030` → 3000 | 3000 | `artifacts` (rw) |

### Shared volume

Named volume `artifacts` mounted at `/workspace/artifacts` on **worker** and **ui**.
This is the "ui / backend / pipeline" sharing: the pipeline writes, the backend reads.
- worker: writes uploaded APK inputs + `findings-*.json` + reports.
- ui (backend): writes uploaded APK to `artifacts/inputs/`, reads `findings-*.json` to
  ingest into Pocketbase, serves report downloads.

Pocketbase keeps its own `pb-data` volume (its SQLite DB + uploaded files). It does not
mount the shared artifacts volume.

### Data flow

```text
browser
  -> ui (Express + multer): writes APK to shared artifacts/inputs/,
       metadata to Pocketbase, starts Temporal workflow
  -> temporal (gRPC, internal): schedules work
  -> worker: analyzes APK from shared volume, writes findings-*.json to shared volume
  -> ui: polls AnalyzeApkWorkflow.getStatus(), ingests findings from shared volume
       into Pocketbase
  <- browser polls ui for run status + findings
```

### android.jar baked into worker

`orchestrator/Dockerfile` gains a stage that downloads a pinned `android.jar`
(`ARG ANDROID_API=34`, source: `github.com/Sable/android-platforms`) into
`/opt/android/android-${ANDROID_API}/android.jar`, and sets
`ENV SAST_ANDROID_JAR=/opt/android/android-34/android.jar`.

This matches the contract in `common/.../AndroidPlatform.java`: `SAST_ANDROID_JAR` is the
explicit-override path checked first. No host SDK mount, no `ANDROID_HOME` guessing.

### Port isolation

- Published host ports: `18030` (UI), `18080` (Temporal UI), `18090` (Pocketbase).
- Temporal gRPC `7233` and `temporal-postgres` `5432` are **not** published — internal only.
- Internal service-to-service traffic uses default ports on the private network, so it
  never overlaps the other stack.
- Compose runs under an explicit project name (`-p oversecured`) so networks/volumes do
  not collide with the other Pocketbase stack.

### Service env contract (for the other agent's UI)

The `ui` service receives:
- `POCKETBASE_URL=http://pocketbase:8090`
- `TEMPORAL_ADDRESS=temporal:7233`
- `ARTIFACT_ROOT=/workspace/artifacts`
- `PORT=3000`

The other agent's job: point `ui/src/server/db.ts` + `auth.ts` at Pocketbase via
`POCKETBASE_URL`, and define PB collections (users, apks, runs, run_nodes, findings).

## Files

- `docker-compose.server.yml` — new, the server stack.
- `orchestrator/Dockerfile` — add a baked-android.jar stage that places the jar at
  `/opt/android/android-${ANDROID_API}/android.jar`. Do **not** bake `SAST_ANDROID_JAR`
  into the image (that would override the dev compose's host-SDK mount). Instead set
  `SAST_ANDROID_JAR` only in `docker-compose.server.yml`'s `worker` env, pointing at the
  baked path. The dev `docker-compose.yml` keeps its host-SDK mount and leaves
  `SAST_ANDROID_JAR` unset, so `ANDROID_HOME` resolution still works there.
- `.env.server.example` — documents `ANDROID_API`, `POCKETBASE_ADMIN_EMAIL/PASSWORD`,
  pinned image tags, host port overrides.
- `docs/server-stack.md` — run instructions, port table, the `git subtree add` command,
  and the Pocketbase/UI contract.

## Error handling / ops

- `worker`: `restart: on-failure` (matches dev).
- `pocketbase`, `ui`, `temporal*`: `restart: unless-stopped`.
- `temporal` depends on `temporal-postgres` healthy; `ui` + `worker` depend on `temporal`
  reachable; `ui` depends on `pocketbase`. Use healthchecks where the images support them.
- First-boot Pocketbase admin is seeded from `.env.server` (`PB superuser` env or first-run
  bootstrap) so the other agent can log in.

## Testing / verification

- `docker compose -f docker-compose.server.yml -p oversecured config` validates the file.
- `docker compose ... up -d` then verify: Temporal UI on `:18080`, PB admin on `:18090`,
  UI on `:18030`; worker logs show it found `SAST_ANDROID_JAR`.
- Confirm no conflict: published ports are all `18xxx`; the other stack's `:8090` is
  untouched.
- A smoke run (upload a test-subject APK) is deferred until the other agent's UI ↔ PB
  wiring lands; until then, verify the worker boots and connects to Temporal.

## Later: subtree adoption

When the other agent's UI repo exists:

```bash
git rm -r ui && git commit -m "chore(ui): drop in-tree scaffold before subtree"
git subtree add --prefix ui <remote-url> <branch> --squash
```

Pull updates later with `git subtree pull --prefix ui <remote-url> <branch> --squash`.
