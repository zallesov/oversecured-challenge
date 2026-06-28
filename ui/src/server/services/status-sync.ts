import type { PoolClient } from "pg";
import { randomUUID } from "node:crypto";

import { query, transaction } from "../db.js";
import {
  buildAnalysisPlan,
  queryRunStatus,
  type WorkflowNodeStatus,
  type WorkflowRunStatus,
} from "../temporal.js";
import {
  extractFindingLocation,
  readFindingsDoc,
  type FindingJson,
} from "./artifacts.js";

type ActiveRunRow = {
  id: string;
  workflow_id: string;
};

function json(value: unknown): string {
  return JSON.stringify(value ?? null);
}

function textOrDefault(value: string | undefined | null, fallback: string): string {
  return value && value.length > 0 ? value : fallback;
}

function findingText(
  finding: FindingJson,
  key: "ruleId" | "vulnerabilityClass" | "severity" | "message" | "cwe" | "owaspMobile",
  fallback = "",
): string {
  const value = finding[key];
  return typeof value === "string" && value.length > 0 ? value : fallback;
}

async function upsertRunStatus(
  client: PoolClient,
  runId: string,
  status: WorkflowRunStatus,
): Promise<void> {
  const report = buildAnalysisPlan(runId).report;

  await client.query(
    `
      UPDATE runs
      SET status = $2,
          message = $3,
          started_at = $4,
          finished_at = $5,
          duration_ms = $6,
          report_html_key = COALESCE(report_html_key, $7),
          report_sarif_key = COALESCE(report_sarif_key, $8),
          updated_at = now()
      WHERE id = $1
    `,
    [
      runId,
      status.state,
      status.message,
      status.startedAt,
      status.finishedAt,
      status.durationMs,
      report.htmlKey,
      report.sarifKey,
    ],
  );
}

async function upsertNodeStatus(
  client: PoolClient,
  runId: string,
  node: WorkflowNodeStatus,
): Promise<void> {
  await client.query(
    `
      INSERT INTO run_nodes (
        run_id,
        node_id,
        label,
        kind,
        state,
        message,
        queued_at,
        started_at,
        finished_at,
        duration_ms,
        finding_count,
        severity_counts,
        metrics,
        diagnostics,
        artifacts,
        error,
        findings_keys,
        updated_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb, $13::jsonb, $14::jsonb, $15::jsonb, $16::jsonb, $17::jsonb, now())
      ON CONFLICT (run_id, node_id)
      DO UPDATE SET
        label = EXCLUDED.label,
        kind = EXCLUDED.kind,
        state = EXCLUDED.state,
        message = EXCLUDED.message,
        queued_at = EXCLUDED.queued_at,
        started_at = EXCLUDED.started_at,
        finished_at = EXCLUDED.finished_at,
        duration_ms = EXCLUDED.duration_ms,
        finding_count = EXCLUDED.finding_count,
        severity_counts = EXCLUDED.severity_counts,
        metrics = EXCLUDED.metrics,
        diagnostics = EXCLUDED.diagnostics,
        artifacts = EXCLUDED.artifacts,
        error = EXCLUDED.error,
        findings_keys = EXCLUDED.findings_keys,
        updated_at = now()
    `,
    [
      runId,
      node.id,
      node.label,
      node.kind,
      node.state,
      node.message,
      node.queuedAt,
      node.startedAt,
      node.finishedAt,
      node.durationMs,
      node.findingCount ?? 0,
      json(node.severityCounts ?? {}),
      json(node.metrics ?? {}),
      json(node.diagnostics ?? []),
      json(node.artifacts ?? []),
      node.error ? json(node.error) : null,
      json(node.findingsKeys ?? []),
    ],
  );
}

async function hasIngestedFindings(
  client: PoolClient,
  runId: string,
  nodeId: string,
): Promise<boolean> {
  const result = await client.query(
    "SELECT findings_ingested FROM run_nodes WHERE run_id = $1 AND node_id = $2",
    [runId, nodeId],
  );
  return result.rows[0]?.findings_ingested === true;
}

async function insertFinding(
  client: PoolClient,
  runId: string,
  nodeId: string,
  analyzer: string,
  finding: FindingJson,
): Promise<void> {
  const location = extractFindingLocation(finding);

  await client.query(
    `
      INSERT INTO findings (
        id,
        run_id,
        node_id,
        analyzer,
        rule_id,
        vulnerability_class,
        severity,
        message,
        cwe,
        owasp_mobile,
        source_file,
        source_line,
        sink_file,
        sink_line,
        raw_json
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15::jsonb)
    `,
    [
      randomUUID(),
      runId,
      nodeId,
      analyzer,
      findingText(finding, "ruleId", "unknown"),
      findingText(finding, "vulnerabilityClass", "unknown"),
      findingText(finding, "severity", "UNKNOWN"),
      findingText(finding, "message", "No message"),
      findingText(finding, "cwe") || null,
      findingText(finding, "owaspMobile") || null,
      location.sourceFile,
      location.sourceLine,
      location.sinkFile,
      location.sinkLine,
      json(finding),
    ],
  );
}

async function ingestFindingsForNode(
  client: PoolClient,
  runId: string,
  node: WorkflowNodeStatus,
): Promise<void> {
  if (
    node.kind !== "analyzer" ||
    node.state !== "COMPLETED" ||
    !Array.isArray(node.findingsKeys) ||
    node.findingsKeys.length === 0 ||
    node.findingCount === 0
  ) {
    return;
  }

  if (await hasIngestedFindings(client, runId, node.id)) {
    return;
  }

  for (const findingsKey of node.findingsKeys) {
    const doc = await readFindingsDoc(findingsKey);
    for (const finding of doc.findings) {
      await insertFinding(client, runId, node.id, doc.analyzer, finding);
    }
  }

  await client.query(
    `
      UPDATE run_nodes
      SET findings_ingested = true,
          updated_at = now()
      WHERE run_id = $1 AND node_id = $2
    `,
    [runId, node.id],
  );
}

async function syncRun(run: ActiveRunRow): Promise<void> {
  const status = await queryRunStatus(run.workflow_id);

  await transaction(async (client) => {
    await upsertRunStatus(client, run.id, status);
    for (const node of status.nodes ?? []) {
      await upsertNodeStatus(client, run.id, node);
    }
  });

  for (const node of status.nodes ?? []) {
    try {
      await transaction(async (client) => {
        await ingestFindingsForNode(client, run.id, node);
      });
    } catch (error) {
      console.error(
        `Failed to ingest findings for run ${run.id} node ${node.id}:`,
        error instanceof Error ? error.message : error,
      );
    }
  }
}

export async function syncActiveRuns(): Promise<void> {
  const activeRuns = await query<ActiveRunRow>(
    "SELECT id, workflow_id FROM runs WHERE status IN ('QUEUED', 'RUNNING') ORDER BY created_at ASC",
  );

  for (const run of activeRuns.rows) {
    try {
      await syncRun(run);
    } catch (error) {
      console.error(
        `Failed to sync run ${run.id} (${run.workflow_id}):`,
        error instanceof Error ? error.message : error,
      );
    }
  }
}

export function startStatusSync(intervalMs: number): { stop: () => void } {
  let running = false;

  const tick = (): void => {
    if (running) {
      return;
    }
    running = true;
    syncActiveRuns()
      .catch((error) => {
        console.error(
          "Status sync failed:",
          error instanceof Error ? error.message : error,
        );
      })
      .finally(() => {
        running = false;
      });
  };

  tick();
  const interval = setInterval(tick, intervalMs);
  return {
    stop: () => clearInterval(interval),
  };
}
