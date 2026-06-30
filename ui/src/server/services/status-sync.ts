import type { RecordModel } from "pocketbase";

import { adminPb } from "../pb.js";
import { queryRunStatus } from "../temporal.js";
import {
  extractFindingLocation,
  readFindingsDoc,
  type FindingJson,
} from "./artifacts.js";

export type StatusEventState = "RUNNING" | "COMPLETED" | "FAILED";

// Node-status event POSTed by the worker interceptor. Matches the Java StatusEvent wire contract.
export type StatusEvent = {
  runId: string;
  nodeId: string;
  state: StatusEventState;
  message?: string | null;
  occurredAt?: string | null;
  metrics?: Record<string, unknown>;
  findingsKeys?: string[];
  findingCount?: number;
  severityCounts?: Record<string, number>;
  error?: { kind?: string; message?: string } | null;
};

// Mirrors AnalyzeApkWorkflowImpl.nodeDefinitions(); the event carries no label/kind.
const NODE_DEFS: Record<string, { label: string; kind: string }> = {
  decompile: { label: "Decompile", kind: "preparation" },
  parse: { label: "Parse Sources", kind: "preparation" },
  "manifest-facts": { label: "Manifest Facts", kind: "preparation" },
  taint: { label: "Taint Analysis", kind: "analyzer" },
  "manifest-misconfig": { label: "Manifest Misconfiguration", kind: "analyzer" },
  report: { label: "Report", kind: "report" },
  "ai-triage": { label: "AI Triage", kind: "report" },
};
const PIPELINE_NODE_IDS = Object.keys(NODE_DEFS);
// ai-triage is a soft step: its failure never fails the run.
const HARD_NODE_IDS = [
  "decompile",
  "parse",
  "manifest-facts",
  "taint",
  "manifest-misconfig",
  "report",
];

function findingText(
  finding: FindingJson,
  key: string,
  fallback = "",
): string {
  const value = finding[key];
  return typeof value === "string" && value.length > 0 ? value : fallback;
}

function isTerminal(state: StatusEventState): boolean {
  return state === "COMPLETED" || state === "FAILED";
}

function timestamps(values: unknown[]): number[] {
  return values
    .filter((value): value is string => typeof value === "string" && value.length > 0)
    .map((value) => Date.parse(value))
    .filter((value) => !Number.isNaN(value));
}

async function listNodes(
  pb: Awaited<ReturnType<typeof adminPb>>,
  runRecordId: string,
): Promise<RecordModel[]> {
  return pb.collection("run_nodes").getFullList({
    filter: pb.filter("run = {:run}", { run: runRecordId }),
  });
}

/** Apply one worker status event: upsert the node, derive run status, ingest findings. */
export async function applyStatusEvent(
  runRecordId: string,
  event: StatusEvent,
): Promise<void> {
  const pb = await adminPb();
  const occurredAt = event.occurredAt || new Date().toISOString();

  const nodes = await listNodes(pb, runRecordId);
  const byNodeId = new Map<string, RecordModel>(
    nodes.map((node) => [node.nodeId as string, node]),
  );

  // Ensure the full pipeline exists so the graph is complete even before each node starts.
  for (const nodeId of PIPELINE_NODE_IDS) {
    if (!byNodeId.has(nodeId)) {
      const def = NODE_DEFS[nodeId];
      const created = await pb.collection("run_nodes").create({
        run: runRecordId,
        nodeId,
        label: def.label,
        kind: def.kind,
        state: "QUEUED",
        message: "",
        findingCount: 0,
        severityCounts: {},
        metrics: {},
        findingsKeys: [],
        error: null,
        findingsIngested: false,
      });
      byNodeId.set(nodeId, created);
    }
  }

  const def = NODE_DEFS[event.nodeId] ?? {
    label: event.nodeId,
    kind: "analyzer",
  };
  const target = byNodeId.get(event.nodeId)!;

  const prevQueued = (target.queuedAt as string) || "";
  const prevStarted = (target.startedAt as string) || "";
  const queuedAt = prevQueued || occurredAt;
  const startedAt =
    prevStarted ||
    (event.state === "RUNNING" || isTerminal(event.state) ? occurredAt : "");
  const finishedAt = isTerminal(event.state)
    ? occurredAt
    : (target.finishedAt as string) || "";
  const durationMs =
    startedAt && finishedAt
      ? Date.parse(finishedAt) - Date.parse(startedAt)
      : null;

  const nodeFields = {
    run: runRecordId,
    nodeId: event.nodeId,
    label: def.label,
    kind: def.kind,
    state: event.state,
    message: event.message ?? "",
    queuedAt,
    startedAt,
    finishedAt,
    durationMs,
    findingCount: event.findingCount ?? 0,
    severityCounts: event.severityCounts ?? {},
    metrics: event.metrics ?? {},
    findingsKeys: event.findingsKeys ?? [],
    error: event.error ?? null,
  };

  const updatedNode = await pb
    .collection("run_nodes")
    .update(target.id, nodeFields);
  byNodeId.set(event.nodeId, updatedNode);

  await updateRunStatus(pb, runRecordId, event, byNodeId, occurredAt);
  await ingestFindings(pb, runRecordId, event, updatedNode);
}

async function updateRunStatus(
  pb: Awaited<ReturnType<typeof adminPb>>,
  runRecordId: string,
  event: StatusEvent,
  byNodeId: Map<string, RecordModel>,
  occurredAt: string,
): Promise<void> {
  const stateOf = (nodeId: string): string =>
    (byNodeId.get(nodeId)?.state as string) ?? "QUEUED";

  const hardFailed = HARD_NODE_IDS.find((id) => stateOf(id) === "FAILED");
  let status: string;
  let message: string;

  if (hardFailed) {
    status = "FAILED";
    message = `Analysis failed at ${hardFailed}.`;
  } else if (
    stateOf("report") === "COMPLETED" &&
    (stateOf("ai-triage") === "COMPLETED" || stateOf("ai-triage") === "FAILED")
  ) {
    status = "COMPLETED";
    message = "Analysis complete.";
  } else {
    const anyStarted = PIPELINE_NODE_IDS.some((id) => stateOf(id) !== "QUEUED");
    status = anyStarted ? "RUNNING" : "QUEUED";
    message = `Running ${event.nodeId}.`;
  }

  const allNodes = [...byNodeId.values()];
  const starts = timestamps(allNodes.map((n) => n.startedAt));
  const runStartedAt = starts.length
    ? new Date(Math.min(...starts)).toISOString()
    : "";

  let runFinishedAt = "";
  let durationMs: number | null = null;
  if (status === "COMPLETED" || status === "FAILED") {
    const finishes = timestamps(allNodes.map((n) => n.finishedAt));
    runFinishedAt = finishes.length
      ? new Date(Math.max(...finishes)).toISOString()
      : occurredAt;
    if (runStartedAt) {
      durationMs = Date.parse(runFinishedAt) - Date.parse(runStartedAt);
    }
  }

  await pb.collection("runs").update(runRecordId, {
    status,
    message,
    startedAt: runStartedAt,
    finishedAt: runFinishedAt,
    durationMs,
  });
}

async function ingestFindings(
  pb: Awaited<ReturnType<typeof adminPb>>,
  runRecordId: string,
  event: StatusEvent,
  node: RecordModel,
): Promise<void> {
  if (
    event.state !== "COMPLETED" ||
    !event.findingsKeys ||
    event.findingsKeys.length === 0 ||
    (event.findingCount ?? 0) === 0 ||
    node.findingsIngested === true
  ) {
    return;
  }

  try {
    for (const key of event.findingsKeys) {
      const doc = await readFindingsDoc(key);
      for (const finding of doc.findings) {
        const location = extractFindingLocation(finding);
        await pb.collection("findings").create({
          run: runRecordId,
          nodeId: event.nodeId,
          analyzer: doc.analyzer,
          ruleId: findingText(finding, "ruleId", "unknown"),
          vulnerabilityClass: findingText(finding, "vulnerabilityClass", "unknown"),
          severity: findingText(finding, "severity", "UNKNOWN"),
          message: findingText(finding, "message", "No message"),
          cwe: findingText(finding, "cwe") || null,
          owaspMobile: findingText(finding, "owaspMobile") || null,
          sourceFile: location.sourceFile,
          sourceLine: location.sourceLine,
          sinkFile: location.sinkFile,
          sinkLine: location.sinkLine,
          rawJson: finding,
        });
      }
    }
    await pb.collection("run_nodes").update(node.id, { findingsIngested: true });
  } catch (error) {
    console.error(
      `Failed to ingest findings for run ${runRecordId} node ${event.nodeId}:`,
      error instanceof Error ? error.message : error,
    );
  }
}

/**
 * Safety-net sweep (NOT a poll loop): for runs stuck RUNNING past a TTL with no recent event, do a
 * single Temporal reconcile to recover lost best-effort emits or infra-level workflow death.
 */
export function startRunReconcile(intervalMs: number): { stop: () => void } {
  let running = false;

  const tick = async (): Promise<void> => {
    if (running) {
      return;
    }
    running = true;
    try {
      const pb = await adminPb();
      const staleMs = Number(process.env.RUN_STALE_MS ?? 600000);
      const cutoff = new Date(Date.now() - staleMs);
      const stale = await pb.collection("runs").getList(1, 20, {
        filter: pb.filter("status = {:status} && updated < {:cutoff}", {
          status: "RUNNING",
          cutoff,
        }),
      });

      for (const run of stale.items) {
        try {
          const status = await queryRunStatus(run.workflowId as string);
          if (status.state === "COMPLETED" || status.state === "FAILED") {
            await pb.collection("runs").update(run.id, {
              status: status.state,
              message: status.message,
              finishedAt: status.finishedAt ?? "",
              durationMs: status.durationMs ?? null,
            });
          }
        } catch (error) {
          console.error(
            `Run reconcile failed for ${run.id} (${run.workflowId as string}):`,
            error instanceof Error ? error.message : error,
          );
        }
      }
    } catch (error) {
      console.error(
        "Run reconcile sweep failed:",
        error instanceof Error ? error.message : error,
      );
    } finally {
      running = false;
    }
  };

  void tick();
  const interval = setInterval(() => {
    void tick();
  }, intervalMs);
  return {
    stop: () => clearInterval(interval),
  };
}
