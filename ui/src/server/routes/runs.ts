import { unlink } from "node:fs/promises";
import path from "node:path";
import { randomUUID } from "node:crypto";

import { Router, type NextFunction, type Request, type Response } from "express";
import multer from "multer";

import { requireAuth, type AuthenticatedRequest } from "../auth.js";
import { query } from "../db.js";
import {
  artifactRoot,
  calculateSha256,
  ensureUploadTempDir,
  moveUploadedApk,
  resolveArtifactKey,
  runArtifactKey,
  tempUploadFilename,
} from "../services/artifacts.js";
import {
  buildAnalysisPlan,
  startAnalysisWorkflow,
  workflowIdForRun,
} from "../temporal.js";

type RunRow = {
  id: string;
  user_id: string;
  workflow_id: string;
  apk_filename: string;
  apk_sha256: string;
  apk_size_bytes: string | number;
  artifact_root: string;
  status: string;
  message: string;
  started_at: Date | string | null;
  finished_at: Date | string | null;
  duration_ms: string | number | null;
  report_html_key: string | null;
  report_sarif_key: string | null;
  created_at: Date | string;
  updated_at: Date | string;
};

type NodeRow = {
  node_id: string;
  label: string;
  kind: string;
  state: string;
  message: string;
  queued_at: Date | string | null;
  started_at: Date | string | null;
  finished_at: Date | string | null;
  duration_ms: string | number | null;
  finding_count: number;
  severity_counts: unknown;
  metrics: unknown;
  diagnostics: unknown;
  artifacts: unknown;
  error: unknown;
  findings_keys: unknown;
  updated_at: Date | string;
};

type FindingRow = {
  id: string;
  run_id: string;
  node_id: string;
  analyzer: string;
  rule_id: string;
  vulnerability_class: string;
  severity: string;
  message: string;
  cwe: string | null;
  owasp_mobile: string | null;
  source_file: string | null;
  source_line: number | null;
  sink_file: string | null;
  sink_line: number | null;
  raw_json: unknown;
  created_at: Date | string;
};

const router = Router();

const storage = multer.diskStorage({
  destination: (_req, _file, callback) => {
    ensureUploadTempDir()
      .then((dir) => callback(null, dir))
      .catch((error) => callback(error as Error, ""));
  },
  filename: (_req, file, callback) => {
    callback(null, tempUploadFilename(file.originalname));
  },
});

const upload = multer({
  storage,
  limits: {
    fileSize: Number(process.env.MAX_APK_BYTES ?? 250 * 1024 * 1024),
  },
});

function asyncHandler(
  handler: (req: AuthenticatedRequest, res: Response) => Promise<void>,
) {
  return (req: Request, res: Response, next: NextFunction): void => {
    handler(req as AuthenticatedRequest, res).catch(next);
  };
}

function authUser(req: AuthenticatedRequest): { id: string; email: string } {
  if (!req.user) {
    throw new Error("Authenticated user missing");
  }
  return req.user;
}

function toIso(value: Date | string | null): string | null {
  if (value === null) {
    return null;
  }
  return value instanceof Date ? value.toISOString() : value;
}

function toNumber(value: string | number | null): number | null {
  if (value === null) {
    return null;
  }
  return typeof value === "number" ? value : Number(value);
}

function routeParam(value: string | string[] | undefined): string {
  if (typeof value === "string") {
    return value;
  }
  if (Array.isArray(value) && typeof value[0] === "string") {
    return value[0];
  }
  throw new Error("Missing route parameter");
}

function runJson(row: RunRow) {
  return {
    id: row.id,
    workflowId: row.workflow_id,
    apkFilename: row.apk_filename,
    apkSha256: row.apk_sha256,
    apkSizeBytes: toNumber(row.apk_size_bytes),
    artifactRoot: row.artifact_root,
    status: row.status,
    message: row.message,
    startedAt: toIso(row.started_at),
    finishedAt: toIso(row.finished_at),
    durationMs: toNumber(row.duration_ms),
    reportHtmlKey: row.report_html_key,
    reportSarifKey: row.report_sarif_key,
    createdAt: toIso(row.created_at),
    updatedAt: toIso(row.updated_at),
  };
}

function nodeJson(row: NodeRow) {
  return {
    id: row.node_id,
    label: row.label,
    kind: row.kind,
    state: row.state,
    message: row.message,
    queuedAt: toIso(row.queued_at),
    startedAt: toIso(row.started_at),
    finishedAt: toIso(row.finished_at),
    durationMs: toNumber(row.duration_ms),
    findingCount: row.finding_count,
    severityCounts: row.severity_counts ?? {},
    metrics: row.metrics ?? {},
    diagnostics: row.diagnostics ?? [],
    artifacts: row.artifacts ?? [],
    error: row.error ?? null,
    findingsKeys: row.findings_keys ?? [],
    updatedAt: toIso(row.updated_at),
  };
}

function findingJson(row: FindingRow) {
  return {
    id: row.id,
    runId: row.run_id,
    nodeId: row.node_id,
    analyzer: row.analyzer,
    ruleId: row.rule_id,
    vulnerabilityClass: row.vulnerability_class,
    severity: row.severity,
    message: row.message,
    cwe: row.cwe,
    owaspMobile: row.owasp_mobile,
    sourceFile: row.source_file,
    sourceLine: row.source_line,
    sinkFile: row.sink_file,
    sinkLine: row.sink_line,
    rawJson: row.raw_json,
    createdAt: toIso(row.created_at),
  };
}

async function findOwnedRun(
  runId: string,
  userId: string,
): Promise<RunRow | null> {
  const result = await query<RunRow>(
    "SELECT * FROM runs WHERE id = $1 AND user_id = $2",
    [runId, userId],
  );
  return result.rows[0] ?? null;
}

function originalFilename(file: Express.Multer.File): string {
  return path.basename(file.originalname || "input.apk");
}

router.use("/api/runs", requireAuth);

router.post(
  "/api/runs",
  upload.single("apk"),
  asyncHandler(async (req, res) => {
    const user = authUser(req);
    const file = req.file;

    if (!file) {
      res.status(400).json({ error: "APK upload field 'apk' is required" });
      return;
    }

    const runId = randomUUID();
    const workflowId = workflowIdForRun(runId);
    const plan = buildAnalysisPlan(runId);
    let apkPath: string | null = null;

    try {
      apkPath = await moveUploadedApk(file.path, runId);
      const apkSha256 = await calculateSha256(apkPath);

      await query(
        `
          INSERT INTO runs (
            id,
            user_id,
            workflow_id,
            apk_filename,
            apk_sha256,
            apk_size_bytes,
            artifact_root,
            status,
            message,
            report_html_key,
            report_sarif_key
          )
          VALUES ($1, $2, $3, $4, $5, $6, $7, 'QUEUED', 'Uploaded APK', $8, $9)
        `,
        [
          runId,
          user.id,
          workflowId,
          originalFilename(file),
          apkSha256,
          file.size,
          runArtifactKey(runId),
          plan.report.htmlKey,
          plan.report.sarifKey,
        ],
      );

      try {
        const startedWorkflowId = await startAnalysisWorkflow(runId, apkPath);
        await query(
          "UPDATE runs SET workflow_id = $2, status = 'RUNNING', message = 'Analysis workflow started', updated_at = now() WHERE id = $1",
          [runId, startedWorkflowId],
        );
      } catch (error) {
        await query(
          "UPDATE runs SET status = 'FAILED', message = $2, updated_at = now() WHERE id = $1",
          [
            runId,
            `Failed to start analysis workflow: ${
              error instanceof Error ? error.message : String(error)
            }`,
          ],
        );
        res.status(502).json({
          error: "Failed to start analysis workflow",
          detail: error instanceof Error ? error.message : String(error),
          runId,
        });
        return;
      }

      const run = await findOwnedRun(runId, user.id);
      res.status(201).json(run ? runJson(run) : { id: runId });
    } catch (error) {
      if (apkPath === null) {
        await unlink(file.path).catch(() => undefined);
      }
      throw error;
    }
  }),
);

router.get(
  "/api/runs",
  asyncHandler(async (req, res) => {
    const user = authUser(req);
    const result = await query<RunRow>(
      "SELECT * FROM runs WHERE user_id = $1 ORDER BY created_at DESC",
      [user.id],
    );
    res.json(result.rows.map(runJson));
  }),
);

router.get(
  "/api/runs/:id",
  asyncHandler(async (req, res) => {
    const user = authUser(req);
    const run = await findOwnedRun(routeParam(req.params.id), user.id);
    if (!run) {
      res.status(404).json({ error: "Run not found" });
      return;
    }
    res.json(runJson(run));
  }),
);

router.get(
  "/api/runs/:id/nodes",
  asyncHandler(async (req, res) => {
    const user = authUser(req);
    const run = await findOwnedRun(routeParam(req.params.id), user.id);
    if (!run) {
      res.status(404).json({ error: "Run not found" });
      return;
    }

    const result = await query<NodeRow>(
      "SELECT * FROM run_nodes WHERE run_id = $1 ORDER BY updated_at ASC, node_id ASC",
      [run.id],
    );
    res.json(result.rows.map(nodeJson));
  }),
);

router.get(
  "/api/runs/:id/findings",
  asyncHandler(async (req, res) => {
    const user = authUser(req);
    const run = await findOwnedRun(routeParam(req.params.id), user.id);
    if (!run) {
      res.status(404).json({ error: "Run not found" });
      return;
    }

    const result = await query<FindingRow>(
      `
        SELECT *
        FROM findings
        WHERE run_id = $1
        ORDER BY created_at ASC, severity ASC, rule_id ASC
      `,
      [run.id],
    );
    res.json(result.rows.map(findingJson));
  }),
);

router.get(
  "/api/runs/:id/reports/html",
  asyncHandler(async (req, res) => {
    const user = authUser(req);
    const run = await findOwnedRun(routeParam(req.params.id), user.id);
    if (!run?.report_html_key) {
      res.status(404).json({ error: "HTML report not found" });
      return;
    }

    res.type("html");
    res.sendFile(resolveArtifactKey(run.report_html_key, artifactRoot()));
  }),
);

router.get(
  "/api/runs/:id/reports/sarif",
  asyncHandler(async (req, res) => {
    const user = authUser(req);
    const run = await findOwnedRun(routeParam(req.params.id), user.id);
    if (!run?.report_sarif_key) {
      res.status(404).json({ error: "SARIF report not found" });
      return;
    }

    res.type("application/sarif+json");
    res.sendFile(resolveArtifactKey(run.report_sarif_key, artifactRoot()));
  }),
);

export default router;
