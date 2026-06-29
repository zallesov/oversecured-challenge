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
| — | [`benchmark`](benchmark) | DroidBench + OVAA validation |

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
| `ui` | `oversecured-ui` (built) | **18030** | The web app: upload an APK, watch the pipeline graph live, browse findings (incl. AI triage columns), download HTML/SARIF and the triage sidecar. Express + React. |
| `ui-postgres` | `postgres:16` | internal | Stores UI state — users, runs, per-node status, and ingested findings. |
| `worker` | `oversecured-worker` (built) | internal | Runs the pipeline itself as Temporal **activities** in one JVM (decompile → parse ∥ manifest-facts → taint ∥ misconfig → reporter → ai-triage). Ships a baked `android.jar` so framework types resolve on a decompiled APK; reads `OPENROUTER_API_KEY` for the AI triage step. |
| `temporal` | `temporalio/auto-setup:1.29.6` | internal (gRPC) | Durable workflow engine. The pipeline is multi-step with fan-out and retries; Temporal gives durable orchestration, automatic retry with backoff, and a queryable run status that drives the UI graph. |
| `temporal-postgres` | `postgres:16` | internal | Temporal's own datastore. |
| `temporal-ui` | `temporalio/ui:2.51.0` | **18080** | Inspect/debug workflow executions directly. |

**Data plane:** a shared `artifacts` named volume is mounted into both `ui` and `worker`. The UI
writes uploaded APKs there; the worker writes decompiled sources, `findings-*.json`, the HTML/SARIF
reports, and the AI-triage sidecar; the UI reads them back. `rules/` and `test-subjects/` are
bind-mounted read-only into the worker.

**Why this shape:** the orchestrator only *wires* steps — each analyzer is an independent module,
so the worker is one process running them in dependency order under Temporal. The UI is decoupled
and talks to the same Temporal + artifacts. No registry is needed to deploy (images are built
locally, then `docker load`ed on the host).

### Run it locally

Prereqs: Docker (with Buildx). No local JDK/Node needed — images build inside Docker.

```bash
cp .env.server.example .env.server          # then edit it (see below)
docker compose -f docker-compose.server.yml -p oversecured --env-file .env.server up -d --build
```

Required / useful `.env.server` values:

- `JWT_SECRET` — **required**. UI auth signing key. Generate: `openssl rand -hex 32`.
- `OPENROUTER_API_KEY` — optional. Enables the AI triage agent; without it the step is fail-soft
  and writes an empty sidecar.
- `OPENROUTER_MODEL` — optional, default `anthropic/claude-haiku-4.5`.
- `ANDROID_API` — optional, default `34` (the baked `android.jar` level).

Then open:

- UI → http://localhost:18030 (register a user, upload an APK)
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
`docker save`s them, copies the tarballs + compose file + `rules/` + `test-subjects/` + `.env.server`
over SSH, `docker load`s, and brings the stack up under `-p oversecured`:

```bash
SSH_HOST=hermes ./deploy/ship-to-hermes.sh
```

Full details, ports, and volumes: [`docs/server-stack.md`](docs/server-stack.md).

## Build & test (without Docker)

```bash
./gradlew build        # compile + unit tests for every module
./gradlew :apps:ai-triage:test :orchestrator:test
```
