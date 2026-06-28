# UI Database Migrations

The UI database is a read model for run status, node status, and findings shown by the browser-facing UI. Temporal remains the source of truth for active workflow execution and the worker remains private.

Full finding payloads are produced by analyzers as artifacts under the shared artifact root. The UI backend ingests those artifacts into the `findings` table and keeps `runs` and `run_nodes` updated with the latest status, counts, keys, diagnostics, and report pointers.
