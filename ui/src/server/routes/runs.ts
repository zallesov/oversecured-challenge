import { existsSync } from "node:fs";
import { unlink } from "node:fs/promises";
import path from "node:path";
import { randomUUID } from "node:crypto";

import { Router, type NextFunction, type Request, type Response } from "express";
import multer from "multer";
import type { RecordModel } from "pocketbase";

import { requireAuth, type AuthenticatedRequest } from "../auth.js";
import { adminPb } from "../pb.js";
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

function routeParam(value: string | string[] | undefined): string {
  if (typeof value === "string") {
    return value;
  }
  if (Array.isArray(value) && typeof value[0] === "string") {
    return value[0];
  }
  throw new Error("Missing route parameter");
}

// Map a PocketBase `runs` record to the JSON the client expects on create. The browser reads runs
// straight from PocketBase for everything else; this is only the create response.
function runToJson(record: RecordModel) {
  return {
    id: record.id,
    workflowId: record.workflowId as string,
    apkFilename: record.apkFilename as string,
    apkSha256: record.apkSha256 as string,
    apkSizeBytes: record.apkSizeBytes as number,
    artifactRoot: record.artifactRoot as string,
    status: record.status as string,
    message: record.message as string,
    startedAt: (record.startedAt as string) || null,
    finishedAt: (record.finishedAt as string) || null,
    durationMs: (record.durationMs as number) ?? null,
    reportHtmlKey: (record.reportHtmlKey as string) || null,
    reportSarifKey: (record.reportSarifKey as string) || null,
    createdAt: record.created,
    updatedAt: record.updated,
  };
}

async function findOwnedRun(
  runId: string,
  userId: string,
): Promise<RecordModel | null> {
  const pb = await adminPb();
  try {
    const record = await pb.collection("runs").getOne(runId);
    return record.user === userId ? record : null;
  } catch {
    return null;
  }
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

    // App-level runId (uuid) is the workflow + artifact key only. The PocketBase record id is the
    // identity the browser subscribes to and the status callback targets.
    const runId = randomUUID();
    const workflowId = workflowIdForRun(runId);
    const plan = buildAnalysisPlan(runId);
    let apkPath: string | null = null;

    try {
      apkPath = await moveUploadedApk(file.path, runId);
      const apkSha256 = await calculateSha256(apkPath);

      const pb = await adminPb();
      const record = await pb.collection("runs").create({
        user: user.id,
        workflowId,
        apkFilename: originalFilename(file),
        apkSha256,
        apkSizeBytes: file.size,
        artifactRoot: runArtifactKey(runId),
        status: "QUEUED",
        message: "Uploaded APK",
        reportHtmlKey: plan.report.htmlKey,
        reportSarifKey: plan.report.sarifKey,
      });

      const callbackBase =
        process.env.INTERNAL_BASE_URL ?? "http://localhost:3000";
      const callback = {
        url: `${callbackBase}/internal/runs/${record.id}/status`,
        secret: process.env.STATUS_CALLBACK_SECRET ?? "",
        runId: record.id,
      };

      try {
        const startedWorkflowId = await startAnalysisWorkflow(
          runId,
          apkPath,
          callback,
        );
        const updated = await pb.collection("runs").update(record.id, {
          workflowId: startedWorkflowId,
          status: "RUNNING",
          message: "Analysis workflow started",
        });
        res.status(201).json(runToJson(updated));
      } catch (error) {
        const failed = await pb.collection("runs").update(record.id, {
          status: "FAILED",
          message: `Failed to start analysis workflow: ${
            error instanceof Error ? error.message : String(error)
          }`,
        });
        res.status(502).json({
          error: "Failed to start analysis workflow",
          detail: error instanceof Error ? error.message : String(error),
          runId: failed.id,
        });
      }
    } catch (error) {
      if (apkPath === null) {
        await unlink(file.path).catch(() => undefined);
      }
      throw error;
    }
  }),
);

router.get(
  "/api/runs/:id/reports/html",
  asyncHandler(async (req, res) => {
    const user = authUser(req);
    const run = await findOwnedRun(routeParam(req.params.id), user.id);
    if (!run?.reportHtmlKey) {
      res.status(404).json({ error: "HTML report not found" });
      return;
    }

    res.type("html");
    res.sendFile(
      resolveArtifactKey(run.reportHtmlKey as string, artifactRoot()),
    );
  }),
);

router.get(
  "/api/runs/:id/reports/sarif",
  asyncHandler(async (req, res) => {
    const user = authUser(req);
    const run = await findOwnedRun(routeParam(req.params.id), user.id);
    if (!run?.reportSarifKey) {
      res.status(404).json({ error: "SARIF report not found" });
      return;
    }

    res.type("application/sarif+json");
    res.sendFile(
      resolveArtifactKey(run.reportSarifKey as string, artifactRoot()),
    );
  }),
);

router.get(
  "/api/runs/:id/reports/ai-triage",
  asyncHandler(async (req, res) => {
    const user = authUser(req);
    const run = await findOwnedRun(routeParam(req.params.id), user.id);
    if (!run) {
      res.status(404).json({ error: "Run not found" });
      return;
    }

    // The AI triage sidecar is written by the always-on ai-triage step to a deterministic key under
    // the run's artifact root.
    const mdPath = resolveArtifactKey(
      `${run.artifactRoot as string}/ai-triage.md`,
      artifactRoot(),
    );
    if (!existsSync(mdPath)) {
      res.status(404).json({ error: "AI triage report not found" });
      return;
    }

    res.type("text/markdown");
    res.sendFile(mdPath);
  }),
);

export default router;
