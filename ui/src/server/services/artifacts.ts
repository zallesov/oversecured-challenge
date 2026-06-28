import { createHash, randomUUID } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, readFile, rename, copyFile, unlink } from "node:fs/promises";
import path from "node:path";

export type FindingJson = {
  ruleId?: string;
  vulnerabilityClass?: string;
  severity?: string;
  message?: string;
  cwe?: string;
  owaspMobile?: string;
  flow?: unknown;
  [key: string]: unknown;
};

export type FindingsDoc = {
  analyzer: string;
  findings: FindingJson[];
};

export type FindingLocation = {
  sourceFile: string | null;
  sourceLine: number | null;
  sinkFile: string | null;
  sinkLine: number | null;
};

type FlowStep = {
  file?: unknown;
  line?: unknown;
  label?: unknown;
};

export function artifactRoot(): string {
  return path.resolve(process.env.ARTIFACT_ROOT ?? "./artifacts");
}

export function runArtifactKey(runId: string): string {
  return `runs/${runId}`;
}

export function inputApkKey(runId: string): string {
  return `${runArtifactKey(runId)}/input.apk`;
}

export function resolveArtifactKey(
  artifactKey: string,
  root = artifactRoot(),
): string {
  if (
    artifactKey.length === 0 ||
    artifactKey.includes("\0") ||
    path.isAbsolute(artifactKey)
  ) {
    throw new Error("Invalid artifact key");
  }

  const normalized = path.normalize(artifactKey);
  if (normalized === ".." || normalized.startsWith(`..${path.sep}`)) {
    throw new Error("Invalid artifact key");
  }

  const resolvedRoot = path.resolve(root);
  const resolved = path.resolve(resolvedRoot, normalized);
  if (resolved !== resolvedRoot && !resolved.startsWith(`${resolvedRoot}${path.sep}`)) {
    throw new Error("Invalid artifact key");
  }

  return resolved;
}

export async function ensureRunDir(runId: string): Promise<string> {
  const dir = resolveArtifactKey(runArtifactKey(runId));
  await mkdir(dir, { recursive: true });
  return dir;
}

export async function ensureUploadTempDir(): Promise<string> {
  const dir = resolveArtifactKey("tmp-uploads");
  await mkdir(dir, { recursive: true });
  return dir;
}

export function inputApkPath(runId: string): string {
  return resolveArtifactKey(inputApkKey(runId));
}

export async function moveUploadedApk(
  tempPath: string,
  runId: string,
): Promise<string> {
  await ensureRunDir(runId);
  const destination = inputApkPath(runId);
  try {
    await rename(tempPath, destination);
  } catch (error) {
    if (
      typeof error !== "object" ||
      error === null ||
      !("code" in error) ||
      error.code !== "EXDEV"
    ) {
      throw error;
    }
    await copyFile(tempPath, destination);
    await unlink(tempPath);
  }
  return destination;
}

export function tempUploadFilename(originalName: string): string {
  const extension = path.extname(originalName).slice(0, 16) || ".apk";
  return `${randomUUID()}${extension}`;
}

export async function calculateSha256(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = createHash("sha256");
    const stream = createReadStream(filePath);

    stream.on("error", reject);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("end", () => resolve(hash.digest("hex")));
  });
}

function asObject(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null ? value as Record<string, unknown> : {};
}

function stringOrNull(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function integerOrNull(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) ? value : null;
}

export function extractFindingLocation(finding: FindingJson): FindingLocation {
  const flow = Array.isArray(finding.flow)
    ? finding.flow.map((step) => asObject(step) as FlowStep)
    : [];
  const source =
    flow.find((step) => step.label === "source") ?? flow.at(0) ?? {};
  const sink =
    flow.find((step) => step.label === "sink") ??
    flow.at(flow.length - 1) ??
    {};

  return {
    sourceFile: stringOrNull(source.file),
    sourceLine: integerOrNull(source.line),
    sinkFile: stringOrNull(sink.file),
    sinkLine: integerOrNull(sink.line),
  };
}

export async function readFindingsDoc(
  artifactKey: string,
  root = artifactRoot(),
): Promise<FindingsDoc> {
  const file = resolveArtifactKey(artifactKey, root);
  const raw = JSON.parse(await readFile(file, "utf8")) as unknown;
  const object = asObject(raw);
  const analyzer = stringOrNull(object.analyzer) ?? "unknown";
  const findings = Array.isArray(object.findings)
    ? object.findings.map((finding) => asObject(finding) as FindingJson)
    : [];

  return {
    analyzer,
    findings,
  };
}
