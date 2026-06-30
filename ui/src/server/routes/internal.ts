import { timingSafeEqual } from "node:crypto";

import { Router, type NextFunction, type Request, type Response } from "express";

import {
  applyStatusEvent,
  type StatusEvent,
} from "../services/status-sync.js";

const router = Router();

// Machine-to-machine auth: the worker echoes the shared STATUS_CALLBACK_SECRET the backend passed in
// each job's callback header at submit time.
function secretOk(provided: string | undefined): boolean {
  const expected = process.env.STATUS_CALLBACK_SECRET ?? "";
  if (!expected || !provided) {
    return false;
  }
  const a = Buffer.from(provided);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

router.post(
  "/internal/runs/:id/status",
  (req: Request, res: Response, next: NextFunction): void => {
    if (!secretOk(req.header("x-callback-secret"))) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    const runId = String(req.params.id);
    applyStatusEvent(runId, req.body as StatusEvent)
      .then(() => res.status(204).end())
      .catch(next);
  },
);

export default router;
