# UI Run Status Architecture

The browser talks to the internet-facing UI service on port 3000. The UI container serves the web app and API, persists a read model in `ui-postgres`, and uses Temporal APIs to start workflows and query active run state.

Temporal owns active execution. The worker stays private on the compose network, consumes Temporal tasks, and writes analyzer outputs, reports, and finding artifacts under `/workspace/artifacts`.

The UI and worker share `./artifacts:/workspace/artifacts`. The UI database stores the latest run and node status plus ingested findings for fast list/detail views; complete finding payloads originate from artifacts and are ingested by the UI backend.

Flow:

```text
browser -> ui container/API/DB -> Temporal query/start -> private worker -> shared artifacts
```
