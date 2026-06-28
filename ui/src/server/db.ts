import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import pg, { type PoolClient, type QueryResult, type QueryResultRow } from "pg";

const { Pool } = pg;

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

export async function query<T extends QueryResultRow = QueryResultRow>(
  text: string,
  params: unknown[] = [],
): Promise<QueryResult<T>> {
  return pool.query<T>(text, params);
}

export async function transaction<T>(
  fn: (client: PoolClient) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

function migrationDir(): string {
  if (process.env.NODE_ENV === "production") {
    return path.resolve(process.cwd(), "dist/server/migrations");
  }
  return path.join(path.dirname(fileURLToPath(import.meta.url)), "migrations");
}

function isDuplicateObjectError(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error.code === "42P07" || error.code === "42710")
  );
}

export async function runMigrations(): Promise<void> {
  const dir = migrationDir();
  let files: string[];

  try {
    files = (await readdir(dir))
      .filter((file) => file.endsWith(".sql"))
      .sort((a, b) => a.localeCompare(b));
  } catch (error) {
    if (
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      error.code === "ENOENT"
    ) {
      return;
    }
    throw error;
  }

  if (files.length === 0) {
    return;
  }

  await query(`
    CREATE TABLE IF NOT EXISTS ui_schema_migrations (
      filename TEXT PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);

  const applied = await query<{ filename: string }>(
    "SELECT filename FROM ui_schema_migrations",
  );
  const appliedFiles = new Set(applied.rows.map((row) => row.filename));

  for (const file of files) {
    if (appliedFiles.has(file)) {
      continue;
    }

    const sql = await readFile(path.join(dir, file), "utf8");
    try {
      await transaction(async (client) => {
        await client.query(sql);
        await client.query(
          "INSERT INTO ui_schema_migrations(filename) VALUES ($1)",
          [file],
        );
      });
    } catch (error) {
      if (!isDuplicateObjectError(error)) {
        throw error;
      }

      console.warn(
        `Migration ${file} appears to have already been applied; recording it as applied.`,
      );
      await query(
        "INSERT INTO ui_schema_migrations(filename) VALUES ($1) ON CONFLICT DO NOTHING",
        [file],
      );
    }
  }
}
