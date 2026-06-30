/// <reference path="../node_modules/pocketbase/dist/pocketbase.es.mjs" />
// PocketBase JS migration — targets PocketBase v0.28.x
// Creates: runs, run_nodes, findings (base collections)
// Auth collection `users` is PocketBase's built-in default — left as-is.

migrate(
  (app) => {
    // -------------------------------------------------------------------------
    // Collection: runs
    // -------------------------------------------------------------------------
    const usersCollection = app.findCollectionByNameOrId("users");

    const runs = new Collection({
      type: "base",
      name: "runs",
      // Backend (superuser) writes bypass rules; browser reads only own rows
      listRule: "user = @request.auth.id",
      viewRule: "user = @request.auth.id",
      createRule: null,
      updateRule: null,
      deleteRule: null,
      fields: [
        {
          type: "relation",
          name: "user",
          required: true,
          maxSelect: 1,
          collectionId: usersCollection.id,
          cascadeDelete: true,
        },
        {
          type: "text",
          name: "workflowId",
          required: true,
        },
        {
          type: "text",
          name: "apkFilename",
          required: true,
        },
        {
          type: "text",
          name: "apkSha256",
        },
        {
          type: "number",
          name: "apkSizeBytes",
        },
        {
          type: "text",
          name: "artifactRoot",
          required: true,
        },
        {
          type: "text",
          name: "status",
          required: true,
        },
        {
          type: "text",
          name: "message",
        },
        {
          type: "date",
          name: "startedAt",
        },
        {
          type: "date",
          name: "finishedAt",
        },
        {
          type: "number",
          name: "durationMs",
        },
        {
          type: "text",
          name: "reportHtmlKey",
        },
        {
          type: "text",
          name: "reportSarifKey",
        },
      ],
      indexes: [
        "CREATE UNIQUE INDEX idx_runs_workflowId ON runs (workflowId)",
        "CREATE INDEX idx_runs_user ON runs (user)",
      ],
    });

    app.save(runs);

    // -------------------------------------------------------------------------
    // Collection: run_nodes
    // -------------------------------------------------------------------------
    const runsCollection = app.findCollectionByNameOrId("runs");

    const runNodes = new Collection({
      type: "base",
      name: "run_nodes",
      listRule: "run.user = @request.auth.id",
      viewRule: "run.user = @request.auth.id",
      createRule: null,
      updateRule: null,
      deleteRule: null,
      fields: [
        {
          type: "relation",
          name: "run",
          required: true,
          maxSelect: 1,
          collectionId: runsCollection.id,
          cascadeDelete: true,
        },
        {
          type: "text",
          name: "nodeId",
          required: true,
        },
        {
          type: "text",
          name: "label",
        },
        {
          type: "text",
          name: "kind",
        },
        {
          type: "text",
          name: "state",
          required: true,
        },
        {
          type: "text",
          name: "message",
        },
        {
          type: "date",
          name: "queuedAt",
        },
        {
          type: "date",
          name: "startedAt",
        },
        {
          type: "date",
          name: "finishedAt",
        },
        {
          type: "number",
          name: "durationMs",
        },
        {
          type: "number",
          name: "findingCount",
        },
        {
          type: "json",
          name: "severityCounts",
        },
        {
          type: "json",
          name: "metrics",
        },
        {
          type: "json",
          name: "diagnostics",
        },
        {
          type: "json",
          name: "artifacts",
        },
        {
          type: "json",
          name: "error",
        },
        {
          type: "json",
          name: "findingsKeys",
        },
        {
          type: "bool",
          name: "findingsIngested",
        },
      ],
      indexes: [
        // Mirrors the old composite PK (run_id, node_id)
        "CREATE UNIQUE INDEX idx_run_nodes_run_nodeId ON run_nodes (run, nodeId)",
      ],
    });

    app.save(runNodes);

    // -------------------------------------------------------------------------
    // Collection: findings
    // -------------------------------------------------------------------------
    const findings = new Collection({
      type: "base",
      name: "findings",
      listRule: "run.user = @request.auth.id",
      viewRule: "run.user = @request.auth.id",
      createRule: null,
      updateRule: null,
      deleteRule: null,
      fields: [
        {
          type: "relation",
          name: "run",
          required: true,
          maxSelect: 1,
          collectionId: runsCollection.id,
          cascadeDelete: true,
        },
        {
          // Plain text — NOT a relation; stores the node_id string
          type: "text",
          name: "nodeId",
        },
        {
          type: "text",
          name: "analyzer",
          required: true,
        },
        {
          type: "text",
          name: "ruleId",
        },
        {
          type: "text",
          name: "vulnerabilityClass",
        },
        {
          type: "text",
          name: "severity",
          required: true,
        },
        {
          type: "text",
          name: "message",
          required: true,
        },
        {
          type: "text",
          name: "cwe",
        },
        {
          type: "text",
          name: "owaspMobile",
        },
        {
          type: "text",
          name: "sourceFile",
        },
        {
          type: "number",
          name: "sourceLine",
        },
        {
          type: "text",
          name: "sinkFile",
        },
        {
          type: "number",
          name: "sinkLine",
        },
        {
          // Carries AI-triage verdict/confidence/fix
          type: "json",
          name: "rawJson",
        },
      ],
      indexes: [
        "CREATE INDEX idx_findings_run ON findings (run)",
      ],
    });

    app.save(findings);
  },

  // ---------------------------------------------------------------------------
  // Down migration — drop all three collections in reverse dependency order
  // ---------------------------------------------------------------------------
  (app) => {
    for (const name of ["findings", "run_nodes", "runs"]) {
      try {
        const col = app.findCollectionByNameOrId(name);
        app.delete(col);
      } catch (_) {
        // already absent — ignore
      }
    }
  }
);
