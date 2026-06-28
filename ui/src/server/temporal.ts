import { Client, Connection } from "@temporalio/client";

const TASK_QUEUE = "android-sast-pipeline";
const WORKFLOW_TYPE = "AnalyzeApkWorkflow";
const DEFAULT_TAINT_RULES = [
  "webview",
  "pathtraversal",
  "intent-redirect",
  "file-theft",
  "login-url-injection",
  "credential-log-leak",
  "credential-intent-exfil",
] as const;

export type AnalysisPlan = {
  runId: string;
  keys: {
    runId: string;
    rootKey: string;
    sourcesDirKey: string;
    manifestKey: string;
    astIndexDirKey: string;
    factsKey: string;
  };
  taintAnalyses: Array<{
    name: string;
    rulePath: string;
    findingsKey: string;
  }>;
  manifestMisconfig: {
    name: string;
    rulePath: string;
    findingsKey: string;
  };
  report: {
    htmlKey: string;
    sarifKey: string;
    aiTriageJsonKey: string;
    aiTriageMdKey: string;
  };
};

export type WorkflowRunStatus = {
  runId: string;
  state: "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED";
  message: string;
  startedAt: string | null;
  finishedAt: string | null;
  durationMs: number | null;
  nodes: WorkflowNodeStatus[];
};

export type WorkflowNodeStatus = {
  id: string;
  label: string;
  kind: string;
  state: "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED";
  message: string;
  queuedAt: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  durationMs: number | null;
  metrics: Record<string, unknown>;
  diagnostics: Array<Record<string, unknown>>;
  artifacts: Array<Record<string, unknown>>;
  error: Record<string, unknown> | null;
  findingsKeys: string[];
  findingCount: number;
  severityCounts: Record<string, number>;
};

let clientPromise: Promise<Client> | null = null;

async function temporalClient(): Promise<Client> {
  if (!clientPromise) {
    clientPromise = Connection.connect({
      address: process.env.TEMPORAL_ADDRESS ?? "localhost:7233",
    }).then((connection) => new Client({ connection }));
  }
  return clientPromise;
}

export function workflowIdForRun(runId: string): string {
  return `android-sast-${runId}`;
}

export function buildAnalysisPlan(runId: string): AnalysisPlan {
  const rootKey = `runs/${runId}`;
  const keys = {
    runId,
    rootKey,
    sourcesDirKey: `${rootKey}/sources`,
    manifestKey: `${rootKey}/sources/AndroidManifest.xml`,
    astIndexDirKey: `${rootKey}/ast-index`,
    factsKey: `${rootKey}/facts.json`,
  };

  return {
    runId,
    keys,
    taintAnalyses: DEFAULT_TAINT_RULES.map((name) => ({
      name,
      rulePath: `rules/${name}.yaml`,
      findingsKey: `${rootKey}/findings-${name}.json`,
    })),
    manifestMisconfig: {
      name: "manifest-misconfig",
      rulePath: "rules/misconfig.yaml",
      findingsKey: `${rootKey}/findings-misconfig.json`,
    },
    report: {
      htmlKey: `${rootKey}/report.html`,
      sarifKey: `${rootKey}/report.sarif`,
      aiTriageJsonKey: `${rootKey}/ai-triage.json`,
      aiTriageMdKey: `${rootKey}/ai-triage.md`,
    },
  };
}

export async function startAnalysisWorkflow(
  runId: string,
  apkPath: string,
): Promise<string> {
  const client = await temporalClient();
  const workflowId = workflowIdForRun(runId);

  const handle = await client.workflow.start(WORKFLOW_TYPE, {
    taskQueue: TASK_QUEUE,
    workflowId,
    args: [{ apkPath, plan: buildAnalysisPlan(runId) }],
  });

  return handle.workflowId;
}

export async function queryRunStatus(
  workflowId: string,
): Promise<WorkflowRunStatus> {
  const client = await temporalClient();
  const handle = client.workflow.getHandle(workflowId);
  return handle.query("getStatus" as never);
}
