const TOKEN_KEY = 'oversecured.ui.token';

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

export function getToken(): string | null {
  return window.localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  window.localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  window.localStorage.removeItem(TOKEN_KEY);
}

function authHeaders(): HeadersInit {
  const token = getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function parseError(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as { error?: string; message?: string };
    return body.error ?? body.message ?? response.statusText;
  } catch {
    return response.statusText;
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  Object.entries(authHeaders()).forEach(([key, value]) => headers.set(key, value));

  if (init.body && !(init.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  const response = await fetch(path, { ...init, headers });
  if (!response.ok) {
    throw new ApiError(response.status, await parseError(response));
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return (await response.json()) as T;
}

export const api = {
  async register(email: string, password: string): Promise<AuthResponse> {
    return request<AuthResponse>('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password })
    });
  },

  async login(email: string, password: string): Promise<AuthResponse> {
    return request<AuthResponse>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password })
    });
  },

  async me(): Promise<User> {
    return request<User>('/auth/me');
  },

  async uploadRun(apk: File): Promise<Run> {
    const body = new FormData();
    body.append('apk', apk);
    return request<Run>('/api/runs', { method: 'POST', body });
  },

  async listRuns(): Promise<Run[]> {
    return request<Run[]>('/api/runs');
  },

  async getRun(id: string): Promise<Run> {
    return request<Run>(`/api/runs/${encodeURIComponent(id)}`);
  },

  async getRunNodes(id: string): Promise<RunNode[]> {
    return request<RunNode[]>(`/api/runs/${encodeURIComponent(id)}/nodes`);
  },

  async getRunFindings(id: string): Promise<Finding[]> {
    return request<Finding[]>(`/api/runs/${encodeURIComponent(id)}/findings`);
  },

  async getReport(id: string, kind: 'html' | 'sarif'): Promise<Blob> {
    const response = await fetch(`/api/runs/${encodeURIComponent(id)}/reports/${kind}`, {
      headers: authHeaders()
    });
    if (!response.ok) {
      throw new ApiError(response.status, await parseError(response));
    }
    return response.blob();
  }
};
