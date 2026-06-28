import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import assert from "node:assert/strict";

import {
  extractFindingLocation,
  readFindingsDoc,
  resolveArtifactKey,
} from "./artifacts.js";

test("resolveArtifactKey rejects traversal outside artifact root", () => {
  const root = path.join(tmpdir(), "artifact-root");

  assert.throws(
    () => resolveArtifactKey("../etc/passwd", root),
    /Invalid artifact key/,
  );
});

test("readFindingsDoc extracts source and sink from finding flow", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "artifact-findings-"));
  const key = "runs/run-1/findings-webview.json";
  const file = path.join(root, key);

  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(
    file,
    JSON.stringify({
      analyzer: "taint-engine",
      findings: [
        {
          ruleId: "ANDROID_WEBVIEW_INTENT_LOADURL",
          vulnerabilityClass: "webview-open-redirect",
          severity: "ERROR",
          message: "Untrusted deeplink data flows into WebView.loadUrl",
          flow: [
            { file: "DeeplinkActivity.java", line: 47, label: "source" },
            { file: "BrowserActivity.java", line: 88, label: "sink" },
          ],
        },
      ],
    }),
  );

  try {
    const doc = await readFindingsDoc(key, root);
    const location = extractFindingLocation(doc.findings[0]);

    assert.equal(doc.analyzer, "taint-engine");
    assert.deepEqual(location, {
      sourceFile: "DeeplinkActivity.java",
      sourceLine: 47,
      sinkFile: "BrowserActivity.java",
      sinkLine: 88,
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
