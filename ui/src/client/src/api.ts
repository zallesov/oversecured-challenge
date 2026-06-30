/// <reference types="vite/client" />
import PocketBase from 'pocketbase';
import type { RecordModel, UnsubscribeFunc } from 'pocketbase';

// ---------------------------------------------------------------------------
// Shared PocketBase client — exported so Task 7 can attach realtime listeners
// ---------------------------------------------------------------------------
export const pb = new PocketBase(
  import.meta.env.VITE_POCKETBASE_URL ?? 'http://localhost:8090'
);

// ---------------------------------------------------------------------------
// Types (unchanged)
// ---------------------------------------------------------------------------
export type RunStatus = 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED';
export type NodeState = RunStatus;
export type Severity = 'ERROR' | 'WARNING' | 'NOTE' | 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | string;

export type User = {
  id: string;
  email: string;
};

export type AuthResponse = {
  token: string;
  user: User;
};

export type Run = {
  id: string;
  workflowId?: string;
  apkFilename: string;
  apkSha256?: string;
  apkSizeBytes?: number;
  artifactRoot?: string;
  status: RunStatus;
  message?: string | null;
  startedAt?: string | null;
  finishedAt?: string | null;
  durationMs?: number | null;
  reportHtmlKey?: string | null;
  reportSarifKey?: string | null;
  createdAt?: string;
  updatedAt?: string;
  nodes?: RunNode[];
};

export type RunNode = {
  id: string;
  label: string;
  kind: string;
  state: NodeState;
  message?: string | null;
  queuedAt?: string | null;
  startedAt?: string | null;
  finishedAt?: string | null;
  durationMs?: number | null;
  findingCount: number;
  severityCounts: Record<string, number>;
  metrics: Record<string, unknown>;
  diagnostics: Array<{ where?: string; detail: string }>;
  artifacts: Array<{ type: string; key: string }>;
  error?: { kind?: string; message: string } | null;
  findingsKeys?: string[];
  findingsIngested?: boolean;
  updatedAt?: string;
};

export type Finding = {
  id: string;
  runId?: string;
  nodeId?: string | null;
  analyzer: string;
  ruleId?: string | null;
  vulnerabilityClass?: string | null;
  severity: Severity;
  message: string;
  cwe?: string | null;
  owaspMobile?: string | null;
  sourceFile?: string | null;
  sourceLine?: number | null;
  sinkFile?: string | null;
  sinkLine?: number | null;
  verdict?: string | null;
  confidence?: number | null;
  fix?: string | null;
  rawJson?: unknown;
  createdAt?: string;
};

export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

// ---------------------------------------------------------------------------
// Token helpers — delegated to PocketBase authStore
// ---------------------------------------------------------------------------

/** Returns the current PB auth token, or null if unauthenticated. */
export function getToken(): string | null {
  return pb.authStore.token || null;
}

/** No-op: PocketBase manages its own authStore persistence. Kept for API compat. */
export function setToken(_token: string): void {
  // PocketBase persists its own authStore — no action needed.
}

/** Clears the PocketBase authStore (logs out). */
export function clearToken(): void {
  pb.authStore.clear();
}

// ---------------------------------------------------------------------------
// Fetch helper for backend endpoints that still require a bearer token
// (uploadRun POSTs to /api/runs; getReport fetches blobs from /api/runs/…)
// ---------------------------------------------------------------------------
async function parseError(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as { error?: string; message?: string };
    return body.error ?? body.message ?? response.statusText;
  } catch {
    return response.statusText;
  }
}

function bearerHeaders(): HeadersInit {
  const token = getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

// ---------------------------------------------------------------------------
// Record → type mappers
// ---------------------------------------------------------------------------

function toUser(record: RecordModel): User {
  return {
    id: record.id,
    email: record['email'] as string,
  };
}

function toRun(record: RecordModel): Run {
  return {
    id: record.id,
    workflowId: record['workflowId'] as string | undefined,
    apkFilename: record['apkFilename'] as string,
    apkSha256: record['apkSha256'] as string | undefined,
    apkSizeBytes: record['apkSizeBytes'] as number | undefined,
    artifactRoot: record['artifactRoot'] as string | undefined,
    status: record['status'] as RunStatus,
    message: (record['message'] as string | null | undefined) ?? null,
    startedAt: (record['startedAt'] as string | null | undefined) || null,
    finishedAt: (record['finishedAt'] as string | null | undefined) || null,
    durationMs: (record['durationMs'] as number | null | undefined) ?? null,
    reportHtmlKey: (record['reportHtmlKey'] as string | null | undefined) || null,
    reportSarifKey: (record['reportSarifKey'] as string | null | undefined) || null,
    createdAt: record.created,
    updatedAt: record.updated,
  };
}

function toNode(record: RecordModel): RunNode {
  return {
    id: record['nodeId'] as string,
    label: record['label'] as string,
    kind: record['kind'] as string,
    state: record['state'] as NodeState,
    message: (record['message'] as string | null | undefined) ?? null,
    queuedAt: (record['queuedAt'] as string | null | undefined) || null,
    startedAt: (record['startedAt'] as string | null | undefined) || null,
    finishedAt: (record['finishedAt'] as string | null | undefined) || null,
    durationMs: (record['durationMs'] as number | null | undefined) ?? null,
    findingCount: (record['findingCount'] as number) ?? 0,
    severityCounts: (record['severityCounts'] as Record<string, number>) ?? {},
    metrics: (record['metrics'] as Record<string, unknown>) ?? {},
    diagnostics: (record['diagnostics'] as Array<{ where?: string; detail: string }>) ?? [],
    artifacts: (record['artifacts'] as Array<{ type: string; key: string }>) ?? [],
    error: (record['error'] as { kind?: string; message: string } | null) ?? null,
    findingsKeys: (record['findingsKeys'] as string[]) ?? [],
    findingsIngested: record['findingsIngested'] as boolean | undefined,
    updatedAt: record.updated,
  };
}

function toFinding(record: RecordModel): Finding {
  const raw = (record['rawJson'] as Record<string, unknown>) ?? {};
  return {
    id: record.id,
    runId: record['run'] as string | undefined,
    nodeId: (record['nodeId'] as string | null | undefined) ?? null,
    analyzer: record['analyzer'] as string,
    ruleId: (record['ruleId'] as string | null | undefined) ?? null,
    vulnerabilityClass: (record['vulnerabilityClass'] as string | null | undefined) ?? null,
    severity: record['severity'] as Severity,
    message: record['message'] as string,
    cwe: (record['cwe'] as string | null | undefined) ?? null,
    owaspMobile: (record['owaspMobile'] as string | null | undefined) ?? null,
    sourceFile: (record['sourceFile'] as string | null | undefined) ?? null,
    sourceLine: (record['sourceLine'] as number | null | undefined) ?? null,
    sinkFile: (record['sinkFile'] as string | null | undefined) ?? null,
    sinkLine: (record['sinkLine'] as number | null | undefined) ?? null,
    rawJson: raw,
    verdict: (raw['verdict'] as string | null | undefined) ?? null,
    confidence: (raw['confidence'] as number | null | undefined) ?? null,
    fix: (raw['fix'] as string | null | undefined) ?? null,
    createdAt: record.created,
  };
}

// ---------------------------------------------------------------------------
// Shared upsert helper — replace-or-append by id on create/update, remove on delete
// ---------------------------------------------------------------------------
export function upsertById<T extends { id: string }>(list: T[], item: T, action: string): T[] {
  if (action === 'delete') {
    return list.filter((el) => el.id !== item.id);
  }
  const idx = list.findIndex((el) => el.id === item.id);
  if (idx >= 0) {
    const next = [...list];
    next[idx] = item;
    return next;
  }
  return [...list, item];
}

// ---------------------------------------------------------------------------
// API surface (same exported names and signatures as before)
// ---------------------------------------------------------------------------
export const api = {
  async register(email: string, password: string): Promise<AuthResponse> {
    await pb.collection('users').create({ email, password, passwordConfirm: password });
    const result = await pb.collection('users').authWithPassword(email, password);
    return {
      token: pb.authStore.token,
      user: toUser(result.record),
    };
  },

  async login(email: string, password: string): Promise<AuthResponse> {
    const result = await pb.collection('users').authWithPassword(email, password);
    return {
      token: pb.authStore.token,
      user: toUser(result.record),
    };
  },

  async me(): Promise<User> {
    if (pb.authStore.record) {
      return toUser(pb.authStore.record);
    }
    const result = await pb.collection('users').authRefresh();
    return toUser(result.record);
  },

  /** Upload an APK — still goes to the backend REST API. */
  async uploadRun(apk: File): Promise<Run> {
    const body = new FormData();
    body.append('apk', apk);
    const response = await fetch('/api/runs', {
      method: 'POST',
      headers: bearerHeaders(),
      body,
    });
    if (!response.ok) {
      throw new ApiError(response.status, await parseError(response));
    }
    return (await response.json()) as Run;
  },

  async listRuns(): Promise<Run[]> {
    const records = await pb.collection('runs').getFullList({ sort: '-created' });
    return records.map(toRun);
  },

  async getRun(id: string): Promise<Run> {
    const record = await pb.collection('runs').getOne(id);
    return toRun(record);
  },

  async getRunNodes(id: string): Promise<RunNode[]> {
    const records = await pb.collection('run_nodes').getFullList({
      filter: pb.filter('run = {:r}', { r: id }),
      sort: 'created',
    });
    return records.map(toNode);
  },

  async getRunFindings(id: string): Promise<Finding[]> {
    const records = await pb.collection('findings').getFullList({
      filter: pb.filter('run = {:r}', { r: id }),
      sort: 'created',
    });
    return records.map(toFinding);
  },

  // -------------------------------------------------------------------------
  // Realtime subscription helpers
  // -------------------------------------------------------------------------
  async subscribeRun(id: string, cb: (run: Run) => void): Promise<UnsubscribeFunc> {
    return pb.collection('runs').subscribe(id, (e) => cb(toRun(e.record)));
  },

  async subscribeNodes(id: string, cb: (action: string, node: RunNode) => void): Promise<UnsubscribeFunc> {
    return pb.collection('run_nodes').subscribe('*', (e) => cb(e.action, toNode(e.record)), {
      filter: pb.filter('run = {:r}', { r: id }),
    });
  },

  async subscribeFindings(id: string, cb: (action: string, finding: Finding) => void): Promise<UnsubscribeFunc> {
    return pb.collection('findings').subscribe('*', (e) => cb(e.action, toFinding(e.record)), {
      filter: pb.filter('run = {:r}', { r: id }),
    });
  },

  async subscribeRuns(cb: (action: string, run: Run) => void): Promise<UnsubscribeFunc> {
    return pb.collection('runs').subscribe('*', (e) => cb(e.action, toRun(e.record)));
  },

  /** Download a report — still goes to the backend REST API. */
  async getReport(id: string, kind: 'html' | 'sarif' | 'ai-triage'): Promise<Blob> {
    const response = await fetch(`/api/runs/${encodeURIComponent(id)}/reports/${kind}`, {
      headers: bearerHeaders(),
    });
    if (!response.ok) {
      throw new ApiError(response.status, await parseError(response));
    }
    return response.blob();
  },
};
