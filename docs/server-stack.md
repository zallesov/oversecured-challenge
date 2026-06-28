# Server stack

Self-contained Docker Compose stack for the Android SAST system: Temporal (+ its Postgres
and UI), the analysis worker (with a baked-in `android.jar`), and the web UI (+ its Postgres).
Designed to coexist with unrelated stacks on the same host — all published ports are offset
into the `18xxx` range and the compose project is isolated as `oversecured`.

## Services & ports

| Service | Image | Host port | Internal |
|---|---|---|---|
| `temporal-postgres` | `postgres:16` | — | 5432 |
| `temporal` | `temporalio/auto-setup:1.29.6` | — (internal gRPC) | 7233 |
| `temporal-ui` | `temporalio/ui:2.51.0` | `18080` | 8080 |
| `ui-postgres` | `postgres:16` | — | 5432 |
| `ui` | `oversecured-ui` (built) | `18030` | 3000 |
| `worker` | `oversecured-worker` (built) | — | — |

Only `18030` (UI) and `18080` (Temporal UI) are exposed. Both Postgres DBs and Temporal gRPC
are internal to the compose network.

## Volumes

- `artifacts` (named) — shared between `ui` (writes uploaded APKs, reads findings/reports) and
  `worker` (analyzes APKs, writes `findings-*.json` + reports). Mounted at `/workspace/artifacts`.
- `temporal-postgres`, `ui-postgres` — database data.
- `./rules` (ro) and `./test-subjects` (ro) are bind-mounted into `worker`, so those repo dirs
  must be present alongside the compose file (the deploy script rsyncs them).

## android.jar

`orchestrator/Dockerfile` bakes a pinned `android.jar` (default API 34, from
`github.com/Sable/android-platforms`) at `/opt/android/android-<API>/android.jar`. The image does
**not** set `SAST_ANDROID_JAR` — the server compose sets it in the `worker` env so the dev
compose's host-SDK mount keeps working. Override the level with `ANDROID_API` in `.env.server`.

## Run locally

```bash
cp .env.server.example .env.server   # set JWT_SECRET (openssl rand -hex 32)
docker compose -f docker-compose.server.yml -p oversecured --env-file .env.server up -d --build
```

Verify: UI http://localhost:18030, Temporal UI http://localhost:18080. Worker logs should show
it connected to Temporal; on a run it logs the resolved `SAST_ANDROID_JAR`.

Validate the compose file without starting anything:

```bash
docker compose -f docker-compose.server.yml -p oversecured --env-file .env.server config
```

## Deploy to a remote (no registry)

`deploy/ship-to-hermes.sh` builds the images, `docker save`s them, copies the tarballs + compose
file + `rules/` + `test-subjects/` + `.env.server` to the host, `docker load`s, and brings the
stack up under `-p oversecured`. Usage:

```bash
./deploy/ship-to-hermes.sh                 # host defaults to "hermes", dir ~/oversecured-stack
SSH_HOST=hermes REMOTE_DIR=~/oversecured-stack ./deploy/ship-to-hermes.sh
```

The script never touches other containers; it only manages the `oversecured` project. To stop:

```bash
ssh hermes 'cd ~/oversecured-stack && docker compose -f docker-compose.server.yml -p oversecured --env-file .env.server down'
```

## Later: UI subtree adoption

When the UI moves to its own repo:

```bash
git rm -r ui && git commit -m "chore(ui): drop in-tree scaffold before subtree"
git subtree add --prefix ui <remote-url> <branch> --squash
# later: git subtree pull --prefix ui <remote-url> <branch> --squash
```
