# Android Taint SAST Pipeline

A SAST pipeline that takes an Android **APK**, decompiles it, runs a **taint / dataflow analysis** driven entirely by **external YAML rules**, and emits an **HTML** + **SARIF** report. Built for the OverSecured Coding Challenge (Part 2).

**Primary vulnerability class:** Intent / deeplink data → `WebView.loadUrl` (open redirect / XSS).

Full design: [`docs/superpowers/specs/2026-06-27-android-taint-sast-design.md`](docs/superpowers/specs/2026-06-27-android-taint-sast-design.md).

## Pipeline (6 independent apps + 1 orchestrator)

```
decompiler → { parser ∥ manifest-facts } → fan-out{ taint×rules, manifest-misconfig } → reporter → ai-triage
```

Each step is its own runnable app (own CLI + tests), reading artifacts from earlier steps and writing one artifact. The orchestrator (Temporal) only wires them.

| Step | Module | Role |
|------|--------|------|
| 1 | [`apps/decompiler`](apps/decompiler) | APK → decompiled Java + manifest |
| 2 | [`apps/parser`](apps/parser) | Java → AST + symbol index (parse-once) |
| 3 | [`apps/manifest-facts`](apps/manifest-facts) | manifest → attack-surface facts |
| 4 | [`apps/taint`](apps/taint) | the config-driven taint engine |
| 5 | [`apps/manifest-misconfig`](apps/manifest-misconfig) | manifest misconfiguration findings |
| 6 | [`apps/reporter`](apps/reporter) | merge findings → HTML + SARIF |
| 7 | [`apps/ai-triage`](apps/ai-triage) | AI per-finding triage sidecar (verdict + fix) |
| — | [`orchestrator`](orchestrator) | Temporal workflow (wiring only) |
| — | [`common`](common) | ArtifactStore, findings schema, signature parser |
| — | [`rules`](rules) | external YAML detection rules |

### AI Triage (sidecar)

After the report is built, an AI triage step (`apps/ai-triage`) reads the SARIF
report and decompiled sources in a LangChain4j tool-calling loop and writes
`ai-triage.json` + `ai-triage.md` with a per-finding verdict
(`exploitable` / `needs-review` / `safe`), re-judged severity, and a concrete
fix suggestion.

It is always-on and fail-soft: with no API key or on any error it writes an
empty sidecar and the pipeline still succeeds.

Configure via environment variables:

- `OPENROUTER_API_KEY` — OpenRouter API key (required to actually run the agent).
- `OPENROUTER_MODEL` — model id (default `anthropic/claude-haiku-4.5`).

## Running the full stack (Docker Compose)

The whole system runs as one self-contained Docker Compose stack
([`docker-compose.server.yml`](docker-compose.server.yml)). It is isolated by compose project
name (`-p oversecured`) and all published host ports are offset into the `18xxx` range, so it
coexists with anything else on the host.

### What's in the stack and why

| Service | Image | Host port | Why it exists |
|---|---|---|---|
| `ui` | `oversecured-ui` (built) | **18030** | The web app: upload an APK, watch the pipeline graph live, browse findings (incl. AI triage columns), download HTML/SARIF and the triage sidecar. React client + Express server. The server also owns Temporal (starts the workflow on upload) and applies worker status callbacks into PocketBase. |
| `pocketbase` | `ghcr.io/muchobien/pocketbase:0.28.4` | **18090** (loopback) | The datastore **and** the browser's realtime backend. Holds `users` (auth) plus the `runs` / `run_nodes` / `findings` collections. The React client subscribes to PocketBase realtime, so the pipeline graph and findings update live without polling. Published on `127.0.0.1` only — Traefik is the public edge. |
| `worker` | `oversecured-worker` (built) | internal | Runs the pipeline itself as Temporal **activities** in one JVM (decompile → parse ∥ manifest-facts → taint ∥ misconfig → reporter → ai-triage). Ships a baked `android.jar` so framework types resolve on a decompiled APK; reads `OPENROUTER_API_KEY` for the AI triage step. Emits per-node status back to the `ui` server via a signed callback. |
| `temporal` | `temporalio/auto-setup:1.29.6` | internal (gRPC) | Durable workflow engine. The pipeline is multi-step with fan-out and retries; Temporal gives durable orchestration, automatic retry with backoff, and a queryable run status that drives the UI graph. |
| `temporal-postgres` | `postgres:16` | internal | Temporal's own datastore. |
| `temporal-ui` | `temporalio/ui:2.51.0` | **18080** | Inspect/debug workflow executions directly. |

**Data model (PocketBase):** each upload creates one `runs` row; the pipeline graph is `run_nodes`
(one row per step, seeded on the first worker status event); per-finding rows live in `findings`.
Access rules scope every row to its owning `user`. The `ui` server writes as a PocketBase
**superuser**; the browser reads only its own rows and subscribes to realtime. Collections are
defined by JS migrations in [`ui/pb_migrations`](ui/pb_migrations), bind-mounted into the service.

**Data plane (artifacts):** a shared `artifacts` named volume is mounted into both `ui` and
`worker`. The UI writes uploaded APKs there; the worker writes decompiled sources, `findings-*.json`,
the HTML/SARIF reports, and the AI-triage sidecar; the UI reads them back. `rules/` and
`test-subjects/` are bind-mounted read-only into the worker.

**Why this shape:** the orchestrator only *wires* steps — each analyzer is an independent module,
so the worker is one process running them in dependency order under Temporal. State + realtime live
in PocketBase; heavy artifacts live on the shared volume; the browser talks to PocketBase directly
for live updates and to the Express server for uploads/downloads. No registry is needed to deploy
(images are built locally, then `docker load`ed on the host).

### Run it locally

Prereqs: Docker (with Buildx). No local JDK/Node needed — images build inside Docker.

```bash
cp .env.server.example .env.server          # then edit it (see below)
docker compose -f docker-compose.server.yml -p oversecured --env-file .env.server up -d --build
```

Required / useful `.env.server` values:

- `POCKETBASE_ADMIN_EMAIL` / `POCKETBASE_ADMIN_PASSWORD` — **required**. The PocketBase superuser the
  `ui` server authenticates as to read/write collections. Must match on both services.
- `STATUS_CALLBACK_SECRET` — **required**. Shared secret the worker signs its per-node status
  callbacks with, and the `ui` server validates. Generate: `openssl rand -hex 32`.
- `VITE_POCKETBASE_URL` — browser-reachable PocketBase URL, **baked into the client bundle at build
  time**. Local: `http://localhost:18090`. Remote: the public host (e.g. `https://pb-oversecured.zall.dev`).
- `OPENROUTER_API_KEY` — optional. Enables the AI triage agent; without it the step is fail-soft
  and writes an empty sidecar.
- `OPENROUTER_MODEL` — optional, default `anthropic/claude-haiku-4.5`.
- `ANDROID_API` — optional, default `34` (the baked `android.jar` level).
- `POCKETBASE_PORT` / `UI_PORT` / `TEMPORAL_UI_PORT` — optional host-port overrides (default `18090` / `18030` / `18080`).

> On a fresh `pb-data` volume PocketBase has no superuser yet. Create it once so the `ui` server can
> authenticate (the collection migrations run automatically):
> ```bash
> docker exec oversecured-pocketbase-1 /usr/local/bin/pocketbase \
>   superuser upsert "$POCKETBASE_ADMIN_EMAIL" "$POCKETBASE_ADMIN_PASSWORD" --dir /pb_data
> ```

Then open:

- UI → http://localhost:18030 (register a user, upload an APK)
- PocketBase admin → http://localhost:18090/_/
- Temporal UI → http://localhost:18080

Validate the compose file without starting anything:

```bash
docker compose -f docker-compose.server.yml -p oversecured --env-file .env.server config
```

Stop / tear down:

```bash
docker compose -f docker-compose.server.yml -p oversecured --env-file .env.server down
```

### Deploy to a remote host (no registry)

[`deploy/ship-to-hermes.sh`](deploy/ship-to-hermes.sh) builds the images for the remote's arch,
`docker save`s them, copies the tarballs + compose file + `rules/` + `test-subjects/` +
`ui/pb_migrations/` + `.env.server` over SSH, `docker load`s, and brings the stack up under
`-p oversecured`:

```bash
SSH_HOST=hermes ./deploy/ship-to-hermes.sh
```

PocketBase is published on loopback only; the public edge is Traefik. The file-provider route in
[`deploy/traefik/pb-oversecured.yml`](deploy/traefik/pb-oversecured.yml) maps
`pb-oversecured.zall.dev → 127.0.0.1:18090` (drop it into Traefik's watched config dir). After the
first deploy, create the PocketBase superuser once (see the note above).

Full details, ports, and volumes: [`docs/server-stack.md`](docs/server-stack.md).

## Build & test (without Docker)

```bash
./gradlew build        # compile + unit tests for every module
./gradlew :apps:ai-triage:test :orchestrator:test
```
