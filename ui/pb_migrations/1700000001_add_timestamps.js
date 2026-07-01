/// <reference path="../node_modules/pocketbase/dist/pocketbase.es.mjs" />
// Adds standard `created` / `updated` autodate fields to runs, run_nodes, findings.
// The initial migration (1700000000) omitted them, so the UI's `sort=-created` list
// query 400'd ("Something went wrong"). Autodate fields make created/updated sortable.
// Idempotent: skips a field that already exists.

migrate(
  (app) => {
    const withTimestamps = ["runs", "run_nodes", "findings"];
    for (const name of withTimestamps) {
      const col = app.findCollectionByNameOrId(name);

      if (!col.fields.getByName("created")) {
        col.fields.add(
          new Field({
            type: "autodate",
            name: "created",
            onCreate: true,
            onUpdate: false,
          })
        );
      }
      if (!col.fields.getByName("updated")) {
        col.fields.add(
          new Field({
            type: "autodate",
            name: "updated",
            onCreate: true,
            onUpdate: true,
          })
        );
      }

      app.save(col);
    }
  },

  // Down: drop the two autodate fields from each collection.
  (app) => {
    const withTimestamps = ["runs", "run_nodes", "findings"];
    for (const name of withTimestamps) {
      try {
        const col = app.findCollectionByNameOrId(name);
        for (const field of ["updated", "created"]) {
          const f = col.fields.getByName(field);
          if (f) col.fields.removeById(f.id);
        }
        app.save(col);
      } catch (_) {
        // collection already absent — ignore
      }
    }
  }
);
