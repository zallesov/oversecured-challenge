# UI Run Status Graph Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the backend contract needed for a UI that authenticates users, uploads APKs, starts Temporal scans, polls status, renders a pipeline graph with readable per-step messages, timestamps, durations, errors, and finding counts, and stores run/finding data in a database.

**Architecture:** Temporal remains the execution source of truth while a run is active. The UI backend starts workflows, polls `getStatus()`, persists run/node/finding snapshots to its database, and serves browser polling endpoints. The pipeline worker stays private and communicates artifacts through the shared volume.

**Tech Stack:** Java 17, Gradle, Temporal Java SDK 1.36.0, existing shared artifact filesystem, Postgres for UI metadata, future TypeScript UI/backend container.

---

## Scope

This plan intentionally starts with the status/reporting contract in the existing Java pipeline. The UI app and database can be implemented cleanly only after the workflow exposes stable node snapshots.

The first implementation slice delivers:

- Workflow query: `AnalyzeApkWorkflow.getStatus()`
- Per-node state: queued, running, completed, failed
- Per-node timestamps: `queuedAt`, `startedAt`, `finishedAt`, `durationMs`
- Per-node readable `message`
- Per-node `metrics`, `diagnostics`, `artifacts`, and `error`
- Per-analyzer node `findingCount` and severity counts. Taint is one analyzer node that runs all selected rules sequentially and reports per-rule summaries.
- Activity result objects that return artifact keys and UI telemetry

The second implementation slice adds:

- UI DB schema for runs, run nodes, and findings
- UI backend endpoints for upload, run list, run detail, node status, and findings
- Polling bridge from Temporal to DB
- Frontend graph rendering from the node status payload

## File Structure

### Existing Files To Modify

- `orchestrator/src/main/java/com/oversecured/sast/orchestrator/workflow/AnalyzeApkWorkflow.java`
  - Add `@QueryMethod RunStatus getStatus()`.

- `orchestrator/src/main/java/com/oversecured/sast/orchestrator/workflow/AnalyzeApkWorkflowImpl.java`
  - Maintain workflow-local `RunStatus`.
  - Mark nodes running/completed/failed.
  - Convert activity results into node snapshots.

- `orchestrator/src/main/java/com/oversecured/sast/orchestrator/activities/PipelineActivities.java`
  - Change activity return types from raw strings to structured result objects where needed.

- `orchestrator/src/main/java/com/oversecured/sast/orchestrator/activities/PipelineActivitiesImpl.java`
  - Compute per-step metrics and messages.
  - Count findings after analyzer output files are written. The taint activity is a single batched activity that emits one findings artifact per rule.

- `orchestrator/src/test/java/com/oversecured/sast/orchestrator/AnalyzeApkWorkflowTest.java`
  - Update test activity stubs for new return types.
  - Add query/status tests.

- `orchestrator/src/test/java/com/oversecured/sast/orchestrator/PipelineActivitiesImplTest.java`
  - Assert activity results include messages, timestamps-neutral metrics, artifact references, and finding counts.

- `docker-compose.yml`
  - Later: add UI database and UI app services.
  - Keep Temporal and worker internal in production-oriented compose profile.

- `settings.gradle`
  - Later: add UI backend module only if the UI backend is implemented in Java. If UI backend is TypeScript, no Gradle change.

### New Java Status Contract Files

- `orchestrator/src/main/java/com/oversecured/sast/orchestrator/status/StepState.java`
  - Enum: `QUEUED`, `RUNNING`, `COMPLETED`, `FAILED`.

- `orchestrator/src/main/java/com/oversecured/sast/orchestrator/status/ArtifactRef.java`
  - Small artifact reference for UI links and backend ingestion.

- `orchestrator/src/main/java/com/oversecured/sast/orchestrator/status/StepError.java`
  - Sanitized error information for UI.

- `orchestrator/src/main/java/com/oversecured/sast/orchestrator/status/StepDiagnostic.java`
  - Recoverable warning/detail item.

- `orchestrator/src/main/java/com/oversecured/sast/orchestrator/status/StepResult.java`
  - Successful activity result.

- `orchestrator/src/main/java/com/oversecured/sast/orchestrator/status/NodeStatus.java`
  - Workflow query snapshot for one graph node.

- `orchestrator/src/main/java/com/oversecured/sast/orchestrator/status/RunStatus.java`
  - Workflow query snapshot for the whole run graph.

- `orchestrator/src/main/java/com/oversecured/sast/orchestrator/status/RunStatusBuilder.java`
  - Workflow-owned mutable helper for marking node lifecycle transitions.

### Future UI App Files

Use this structure if implementing the UI as one TypeScript container containing both API and frontend:

- `ui/package.json`
- `ui/Dockerfile`
- `ui/src/server/index.ts`
- `ui/src/server/db.ts`
- `ui/src/server/temporal.ts`
- `ui/src/server/routes/auth.ts`
- `ui/src/server/routes/runs.ts`
- `ui/src/server/services/artifacts.ts`
- `ui/src/server/services/status-sync.ts`
- `ui/src/server/migrations/001_init.sql`
- `ui/src/client/App.tsx`
- `ui/src/client/components/PipelineGraph.tsx`
- `ui/src/client/components/RunList.tsx`
- `ui/src/client/components/RunDetail.tsx`
- `ui/src/client/components/FindingTable.tsx`

---

## Task 1: Add Shared Workflow Status Types

**Files:**
- Create: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/status/StepState.java`
- Create: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/status/ArtifactRef.java`
- Create: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/status/StepDiagnostic.java`
- Create: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/status/StepError.java`
- Create: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/status/StepResult.java`
- Create: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/status/NodeStatus.java`
- Create: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/status/RunStatus.java`
- Test: `orchestrator/src/test/java/com/oversecured/sast/orchestrator/status/StepResultTest.java`

- [ ] **Step 1: Write the failing test**

Create `orchestrator/src/test/java/com/oversecured/sast/orchestrator/status/StepResultTest.java`:

```java
package com.oversecured.sast.orchestrator.status;

import static org.assertj.core.api.Assertions.assertThat;

import com.oversecured.sast.common.Severity;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class StepResultTest {

    @Test
    void completedAnalyzerResultCarriesReadableStatusAndFindingCounts() {
        StepResult result = StepResult.completed(
                "taint",
                "Completed taint analysis for 2 rules with 3 findings.",
                Map.of("ruleCount", 2),
                List.of(new ArtifactRef("findings", "runs/run-1/findings-webview.json")),
                List.of("runs/run-1/findings-webview.json"),
                3,
                Map.of(Severity.ERROR, 1, Severity.WARNING, 2));

        assertThat(result.nodeId()).isEqualTo("taint");
        assertThat(result.state()).isEqualTo(StepState.COMPLETED);
        assertThat(result.message()).isEqualTo("Completed taint analysis for 2 rules with 3 findings.");
        assertThat(result.findingsKeys()).containsExactly("runs/run-1/findings-webview.json");
        assertThat(result.findingCount()).isEqualTo(3);
        assertThat(result.severityCounts()).containsEntry(Severity.ERROR, 1);
        assertThat(result.artifacts()).containsExactly(
                new ArtifactRef("findings", "runs/run-1/findings-webview.json"));
    }

    @Test
    void failedResultSanitizesErrorForUi() {
        StepResult result = StepResult.failed(
                "decompile",
                "Decompilation failed: apk is empty.",
                new StepError("PERMANENT", "apk is empty: /workspace/artifacts/runs/run-1/input.apk"));

        assertThat(result.state()).isEqualTo(StepState.FAILED);
        assertThat(result.message()).isEqualTo("Decompilation failed: apk is empty.");
        assertThat(result.error()).isEqualTo(
                new StepError("PERMANENT", "apk is empty: /workspace/artifacts/runs/run-1/input.apk"));
        assertThat(result.findingCount()).isZero();
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```bash
./gradlew :orchestrator:test --tests 'com.oversecured.sast.orchestrator.status.StepResultTest'
```

Expected: compilation fails because the status package does not exist.

- [ ] **Step 3: Add the status records**

Create `orchestrator/src/main/java/com/oversecured/sast/orchestrator/status/StepState.java`:

```java
package com.oversecured.sast.orchestrator.status;

public enum StepState {
    QUEUED,
    RUNNING,
    COMPLETED,
    FAILED
}
```

Create `ArtifactRef.java`:

```java
package com.oversecured.sast.orchestrator.status;

public record ArtifactRef(String type, String key) {
}
```

Create `StepDiagnostic.java`:

```java
package com.oversecured.sast.orchestrator.status;

public record StepDiagnostic(String where, String detail) {
}
```

Create `StepError.java`:

```java
package com.oversecured.sast.orchestrator.status;

public record StepError(String kind, String message) {
}
```

Create `StepResult.java`:

```java
package com.oversecured.sast.orchestrator.status;

import com.oversecured.sast.common.Severity;
import java.util.List;
import java.util.Map;

public record StepResult(
        String nodeId,
        StepState state,
        String message,
        Map<String, Object> metrics,
        List<StepDiagnostic> diagnostics,
        List<ArtifactRef> artifacts,
        StepError error,
        List<String> findingsKeys,
        int findingCount,
        Map<Severity, Integer> severityCounts) {

    public StepResult {
        metrics = metrics == null ? Map.of() : Map.copyOf(metrics);
        diagnostics = diagnostics == null ? List.of() : List.copyOf(diagnostics);
        artifacts = artifacts == null ? List.of() : List.copyOf(artifacts);
        severityCounts = severityCounts == null ? Map.of() : Map.copyOf(severityCounts);
    }

    public static StepResult completed(
            String nodeId,
            String message,
            Map<String, Object> metrics,
            List<ArtifactRef> artifacts) {
        return new StepResult(nodeId, StepState.COMPLETED, message, metrics, List.of(),
                artifacts, null, List.of(), 0, Map.of());
    }

    public static StepResult completed(
            String nodeId,
            String message,
            Map<String, Object> metrics,
            List<ArtifactRef> artifacts,
            List<String> findingsKeys,
            int findingCount,
            Map<Severity, Integer> severityCounts) {
        return new StepResult(nodeId, StepState.COMPLETED, message, metrics, List.of(),
                artifacts, null, findingsKeys, findingCount, severityCounts);
    }

    public static StepResult failed(String nodeId, String message, StepError error) {
        return new StepResult(nodeId, StepState.FAILED, message, Map.of(), List.of(),
                List.of(), error, List.of(), 0, Map.of());
    }
}
```

Create `NodeStatus.java`:

```java
package com.oversecured.sast.orchestrator.status;

import com.oversecured.sast.common.Severity;
import java.util.List;
import java.util.Map;

public record NodeStatus(
        String id,
        String label,
        String kind,
        StepState state,
        String message,
        String queuedAt,
        String startedAt,
        String finishedAt,
        Long durationMs,
        Map<String, Object> metrics,
        List<StepDiagnostic> diagnostics,
        List<ArtifactRef> artifacts,
        StepError error,
        List<String> findingsKeys,
        int findingCount,
        Map<Severity, Integer> severityCounts) {

    public NodeStatus {
        metrics = metrics == null ? Map.of() : Map.copyOf(metrics);
        diagnostics = diagnostics == null ? List.of() : List.copyOf(diagnostics);
        artifacts = artifacts == null ? List.of() : List.copyOf(artifacts);
        severityCounts = severityCounts == null ? Map.of() : Map.copyOf(severityCounts);
    }
}
```

Create `RunStatus.java`:

```java
package com.oversecured.sast.orchestrator.status;

import java.util.List;

public record RunStatus(
        String runId,
        StepState state,
        String message,
        String startedAt,
        String finishedAt,
        Long durationMs,
        List<NodeStatus> nodes) {

    public RunStatus {
        nodes = List.copyOf(nodes);
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run:

```bash
./gradlew :orchestrator:test --tests 'com.oversecured.sast.orchestrator.status.StepResultTest'
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/src/main/java/com/oversecured/sast/orchestrator/status \
        orchestrator/src/test/java/com/oversecured/sast/orchestrator/status/StepResultTest.java
git commit -m "feat(orchestrator): add run status contract"
```

---

## Task 2: Add Run Status Builder With Timestamps And Durations

**Files:**
- Create: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/status/RunStatusBuilder.java`
- Test: `orchestrator/src/test/java/com/oversecured/sast/orchestrator/status/RunStatusBuilderTest.java`

- [ ] **Step 1: Write the failing test**

Create `RunStatusBuilderTest.java`:

```java
package com.oversecured.sast.orchestrator.status;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;

class RunStatusBuilderTest {

    @Test
    void marksNodeLifecycleWithTimestampsAndDuration() {
        MutableTimeSource timeSource = new MutableTimeSource(Instant.parse("2026-06-28T10:00:00Z"));
        RunStatusBuilder builder = new RunStatusBuilder(
                "run-1",
                List.of(new RunStatusBuilder.NodeDefinition("decompile", "Decompile APK", "step")),
                timeSource);

        builder.markRunning("decompile", "Decompiling APK.");
        timeSource.now = Instant.parse("2026-06-28T10:00:03Z");
        builder.markCompleted(StepResult.completed(
                "decompile",
                "Decompiled APK into 842 source files.",
                Map.of("sourceFileCount", 842),
                List.of(new ArtifactRef("sources", "runs/run-1/sources"))));

        RunStatus status = builder.snapshot();

        assertThat(status.state()).isEqualTo(StepState.COMPLETED);
        NodeStatus node = status.nodes().get(0);
        assertThat(node.state()).isEqualTo(StepState.COMPLETED);
        assertThat(node.startedAt()).isEqualTo("2026-06-28T10:00:00Z");
        assertThat(node.finishedAt()).isEqualTo("2026-06-28T10:00:03Z");
        assertThat(node.durationMs()).isEqualTo(3000);
        assertThat(node.message()).isEqualTo("Decompiled APK into 842 source files.");
        assertThat(node.metrics()).containsEntry("sourceFileCount", 842);
    }

    @Test
    void failedNodeFailsWholeRunSnapshot() {
        MutableTimeSource timeSource = new MutableTimeSource(Instant.parse("2026-06-28T10:00:00Z"));
        RunStatusBuilder builder = new RunStatusBuilder(
                "run-1",
                List.of(new RunStatusBuilder.NodeDefinition("parse", "Parse Sources", "step")),
                timeSource);

        builder.markRunning("parse", "Parsing source files.");
        timeSource.now = Instant.parse("2026-06-28T10:00:05Z");
        builder.markFailed("parse", "Parse failed: index directory missing.",
                new StepError("TRANSIENT", "failed to write index"));

        RunStatus status = builder.snapshot();

        assertThat(status.state()).isEqualTo(StepState.FAILED);
        assertThat(status.finishedAt()).isEqualTo("2026-06-28T10:00:05Z");
        assertThat(status.nodes().get(0).durationMs()).isEqualTo(5000);
        assertThat(status.nodes().get(0).error().kind()).isEqualTo("TRANSIENT");
    }

    private static final class MutableTimeSource implements Supplier<Instant> {
        private Instant now;

        private MutableTimeSource(Instant now) {
            this.now = now;
        }

        @Override
        public Instant get() {
            return now;
        }
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
./gradlew :orchestrator:test --tests 'com.oversecured.sast.orchestrator.status.RunStatusBuilderTest'
```

Expected: compilation fails because `RunStatusBuilder` does not exist.

- [ ] **Step 3: Implement `RunStatusBuilder`**

Create `RunStatusBuilder.java`:

```java
package com.oversecured.sast.orchestrator.status;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

public final class RunStatusBuilder {

    public record NodeDefinition(String id, String label, String kind) {
    }

    private final String runId;
    private final Supplier<Instant> timeSource;
    private final Instant startedAt;
    private final Map<String, MutableNode> nodes = new LinkedHashMap<>();
    private StepState runState = StepState.RUNNING;
    private String runMessage = "Scan is running.";
    private Instant finishedAt;

    public RunStatusBuilder(String runId, List<NodeDefinition> definitions, Supplier<Instant> timeSource) {
        this.runId = runId;
        this.timeSource = timeSource;
        this.startedAt = timeSource.get();
        for (NodeDefinition definition : definitions) {
            nodes.put(definition.id(), new MutableNode(definition, startedAt));
        }
    }

    public void markRunning(String nodeId, String message) {
        MutableNode node = node(nodeId);
        node.state = StepState.RUNNING;
        node.message = message;
        node.startedAt = timeSource.get();
    }

    public void markCompleted(StepResult result) {
        MutableNode node = node(result.nodeId());
        node.state = StepState.COMPLETED;
        node.message = result.message();
        node.finishedAt = timeSource.get();
        node.metrics = result.metrics();
        node.diagnostics = result.diagnostics();
        node.artifacts = result.artifacts();
        node.error = null;
        node.findingsKeys = result.findingsKeys();
        node.findingCount = result.findingCount();
        node.severityCounts = result.severityCounts();
        if (nodes.values().stream().allMatch(n -> n.state == StepState.COMPLETED)) {
            runState = StepState.COMPLETED;
            runMessage = "Scan completed.";
            finishedAt = node.finishedAt;
        }
    }

    public void markFailed(String nodeId, String message, StepError error) {
        MutableNode node = node(nodeId);
        node.state = StepState.FAILED;
        node.message = message;
        node.finishedAt = timeSource.get();
        node.error = error;
        runState = StepState.FAILED;
        runMessage = message;
        finishedAt = node.finishedAt;
    }

    public RunStatus snapshot() {
        return new RunStatus(
                runId,
                runState,
                runMessage,
                format(startedAt),
                format(finishedAt),
                duration(startedAt, finishedAt),
                nodes.values().stream().map(MutableNode::snapshot).toList());
    }

    private MutableNode node(String nodeId) {
        MutableNode node = nodes.get(nodeId);
        if (node == null) {
            throw new IllegalArgumentException("unknown node id: " + nodeId);
        }
        return node;
    }

    private static String format(Instant instant) {
        return instant == null ? null : instant.toString();
    }

    private static Long duration(Instant start, Instant finish) {
        return start == null || finish == null ? null : Duration.between(start, finish).toMillis();
    }

    private static final class MutableNode {
        private final NodeDefinition definition;
        private StepState state = StepState.QUEUED;
        private String message = "Queued.";
        private final Instant queuedAt;
        private Instant startedAt;
        private Instant finishedAt;
        private Map<String, Object> metrics = Map.of();
        private List<StepDiagnostic> diagnostics = List.of();
        private List<ArtifactRef> artifacts = List.of();
        private StepError error;
        private List<String> findingsKeys = List.of();
        private int findingCount;
        private Map<com.oversecured.sast.common.Severity, Integer> severityCounts = Map.of();

        private MutableNode(NodeDefinition definition, Instant queuedAt) {
            this.definition = definition;
            this.queuedAt = queuedAt;
        }

        private NodeStatus snapshot() {
            return new NodeStatus(
                    definition.id(),
                    definition.label(),
                    definition.kind(),
                    state,
                    message,
                    format(queuedAt),
                    format(startedAt),
                    format(finishedAt),
                    duration(startedAt, finishedAt),
                    metrics,
                    diagnostics,
                    artifacts,
                    error,
                    findingsKeys,
                    findingCount,
                    severityCounts);
        }
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
./gradlew :orchestrator:test --tests 'com.oversecured.sast.orchestrator.status.RunStatusBuilderTest'
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/src/main/java/com/oversecured/sast/orchestrator/status/RunStatusBuilder.java \
        orchestrator/src/test/java/com/oversecured/sast/orchestrator/status/RunStatusBuilderTest.java
git commit -m "feat(orchestrator): track node timestamps and durations"
```

---

## Task 3: Change Activity Contracts To Return Step Results

**Files:**
- Modify: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/activities/PipelineActivities.java`
- Modify: `orchestrator/src/test/java/com/oversecured/sast/orchestrator/AnalyzeApkWorkflowTest.java`

- [ ] **Step 1: Update the workflow test stubs first**

In `AnalyzeApkWorkflowTest.java`, import `StepResult` and `ArtifactRef`:

```java
import com.oversecured.sast.orchestrator.status.ArtifactRef;
import com.oversecured.sast.orchestrator.status.StepResult;
import java.util.Map;
```

Change `RecordingActivities` methods to return `StepResult`. Example:

```java
@Override
public synchronized StepResult decompile(DecompileActivityInput input) {
    calls.add("decompile:" + input.sourcesDirKey());
    return StepResult.completed(
            "decompile",
            "Decompiled APK.",
            Map.of(),
            List.of(new ArtifactRef("sources", input.sourcesDirKey())));
}
```

Use these node ids:

```text
decompile
parse
manifest-facts
taint
manifest-misconfig
report
```

For `runTaintBatch`, return one batched taint node:

```java
return StepResult.completed(
        "taint",
        "Completed taint analysis for " + input.rules().size() + " rules with 0 findings.",
        Map.of("ruleCount", input.rules().size()),
        input.rules().stream()
                .map(rule -> new ArtifactRef("findings", rule.findingsKey()))
                .toList(),
        input.rules().stream().map(TaintBatchActivityInput.Rule::findingsKey).toList(),
        0,
        Map.of());
```

For `report`, return:

```java
return StepResult.completed(
        "report",
        "Generated HTML and SARIF reports.",
        Map.of(),
        List.of(
                new ArtifactRef("html", input.htmlKey()),
                new ArtifactRef("sarif", input.sarifKey())));
```

- [ ] **Step 2: Run tests to verify compilation fails at the interface**

```bash
./gradlew :orchestrator:test --tests 'com.oversecured.sast.orchestrator.AnalyzeApkWorkflowTest'
```

Expected: compilation fails because `PipelineActivities` still returns strings and `ReportArtifacts`.

- [ ] **Step 3: Update `PipelineActivities`**

Change `orchestrator/src/main/java/com/oversecured/sast/orchestrator/activities/PipelineActivities.java` to:

```java
package com.oversecured.sast.orchestrator.activities;

import com.oversecured.sast.orchestrator.status.StepResult;
import io.temporal.activity.ActivityInterface;
import io.temporal.activity.ActivityMethod;

@ActivityInterface
public interface PipelineActivities {

    @ActivityMethod
    StepResult decompile(DecompileActivityInput input);

    @ActivityMethod
    StepResult parseSources(ParseActivityInput input);

    @ActivityMethod
    StepResult extractManifestFacts(ManifestFactsActivityInput input);

    @ActivityMethod
    StepResult runTaintBatch(TaintBatchActivityInput input);

    @ActivityMethod
    StepResult runManifestMisconfig(MisconfigActivityInput input);

    @ActivityMethod
    StepResult report(ReportActivityInput input);
}
```

- [ ] **Step 4: Run tests and confirm failures moved to workflow implementation**

```bash
./gradlew :orchestrator:test --tests 'com.oversecured.sast.orchestrator.AnalyzeApkWorkflowTest'
```

Expected: compilation fails in `AnalyzeApkWorkflowImpl`, because it still expects string activity results.

- [ ] **Step 5: Commit the contract change**

```bash
git add orchestrator/src/main/java/com/oversecured/sast/orchestrator/activities/PipelineActivities.java \
        orchestrator/src/test/java/com/oversecured/sast/orchestrator/AnalyzeApkWorkflowTest.java
git commit -m "refactor(orchestrator): return structured step results from activities"
```

---

## Task 4: Implement Activity Step Results And Finding Counts

**Files:**
- Modify: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/activities/PipelineActivitiesImpl.java`
- Test: `orchestrator/src/test/java/com/oversecured/sast/orchestrator/PipelineActivitiesImplTest.java`

- [ ] **Step 1: Add failing tests for activity messages and analyzer counts**

In `PipelineActivitiesImplTest.java`, add assertions for:

```java
StepResult decompile = activities.decompile(new DecompileActivityInput(
        apk.toString(),
        "runs/run-1/sources",
        "runs/run-1/AndroidManifest.xml"));

assertThat(decompile.nodeId()).isEqualTo("decompile");
assertThat(decompile.message()).contains("Decompiled APK");
assertThat(decompile.artifacts()).extracting(ArtifactRef::key)
        .contains("runs/run-1/sources", "runs/run-1/AndroidManifest.xml");
```

Add an analyzer count test by making the test `StepApis.runTaintBatch` write one findings file per rule. For `webview`, write:

```json
{
  "analyzer": "webview",
  "findings": [
    {"ruleId":"webview","vulnerabilityClass":"WebView","severity":"ERROR","message":"m","cwe":"CWE-601","owaspMobile":"M3","flow":[],"notes":[]},
    {"ruleId":"webview","vulnerabilityClass":"WebView","severity":"WARNING","message":"m","cwe":"CWE-601","owaspMobile":"M3","flow":[],"notes":[]}
  ]
}
```

Assert:

```java
assertThat(result.nodeId()).isEqualTo("taint");
assertThat(result.findingCount()).isEqualTo(2);
assertThat(result.severityCounts()).containsEntry(Severity.ERROR, 1);
assertThat(result.severityCounts()).containsEntry(Severity.WARNING, 1);
assertThat(result.findingsKeys()).contains("runs/r1/findings-webview.json");
assertThat(result.message()).isEqualTo("Completed taint analysis for 2 rules with 2 findings.");
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
./gradlew :orchestrator:test --tests 'com.oversecured.sast.orchestrator.PipelineActivitiesImplTest'
```

Expected: compilation failures and/or assertion failures because activities do not return `StepResult` yet.

- [ ] **Step 3: Implement result helpers in `PipelineActivitiesImpl`**

Add imports:

```java
import com.oversecured.sast.common.Finding;
import com.oversecured.sast.common.FindingsDoc;
import com.oversecured.sast.common.Json;
import com.oversecured.sast.common.Severity;
import com.oversecured.sast.orchestrator.status.ArtifactRef;
import com.oversecured.sast.orchestrator.status.StepResult;
import java.util.EnumMap;
import java.util.Map;
```

Add helper methods:

```java
private StepResult taintBatchResult(List<TaintBatchActivityInput.Rule> rules) {
    int total = 0;
    Map<Severity, Integer> severityCounts = new EnumMap<>(Severity.class);
    List<ArtifactRef> artifacts = new ArrayList<>();
    List<String> findingsKeys = new ArrayList<>();
    List<Map<String, Object>> ruleSummaries = new ArrayList<>();
    for (TaintBatchActivityInput.Rule rule : rules) {
        Path findingsJson = paths.resolveArtifactKey(rule.findingsKey());
        FindingsDoc doc = readFindings(findingsJson, rule.findingsKey());
        int ruleCount = doc.findings() == null ? 0 : doc.findings().size();
        total += ruleCount;
        if (doc.findings() != null) {
            for (Finding finding : doc.findings()) {
                severityCounts.merge(finding.severity(), 1, Integer::sum);
            }
        }
        artifacts.add(new ArtifactRef("findings", rule.findingsKey()));
        findingsKeys.add(rule.findingsKey());
        ruleSummaries.add(Map.of("rule", rule.name(), "findingCount", ruleCount));
    }
    return StepResult.completed(
            "taint",
            "Completed taint analysis for " + rules.size() + " rules with " + total + " findings.",
            Map.of("ruleCount", rules.size(), "rules", ruleSummaries),
            artifacts,
            findingsKeys,
            total,
            severityCounts);
}

private StepResult analyzerResult(String nodeId, String label, Path findingsJson, String findingsKey) {
    FindingsDoc doc = readFindings(findingsJson, findingsKey);
    int count = doc.findings() == null ? 0 : doc.findings().size();
    Map<Severity, Integer> severityCounts = new EnumMap<>(Severity.class);
    if (doc.findings() != null) {
        for (Finding finding : doc.findings()) {
            severityCounts.merge(finding.severity(), 1, Integer::sum);
        }
    }
    return StepResult.completed(
            nodeId,
            "Completed " + label + " with " + count + " findings.",
            Map.of(),
            List.of(new ArtifactRef("findings", findingsKey)),
            List.of(findingsKey),
            count,
            severityCounts);
}

private FindingsDoc readFindings(Path findingsJson, String findingsKey) {
    try {
        return Json.read(Files.readAllBytes(findingsJson), FindingsDoc.class);
    } catch (IOException e) {
        throw new UncheckedIOException("failed to read findings for status: " + findingsKey, e);
    }
}

private static int countRegularFiles(Path dir) {
    if (!Files.isDirectory(dir)) {
        return 0;
    }
    try (var stream = Files.walk(dir)) {
        return (int) stream.filter(Files::isRegularFile).count();
    } catch (IOException e) {
        throw new UncheckedIOException("failed to count files under: " + dir, e);
    }
}
```

Change activity methods:

```java
public StepResult decompile(DecompileActivityInput input) {
    Path apk = paths.resolveInputPath(input.apkPath());
    Path sourcesDir = paths.resolveArtifactKey(input.sourcesDirKey());
    apis.decompile(apk, sourcesDir);
    int sourceFileCount = countRegularFiles(sourcesDir);
    return StepResult.completed(
            "decompile",
            "Decompiled APK into " + sourceFileCount + " source files.",
            Map.of("sourceFileCount", sourceFileCount),
            List.of(
                    new ArtifactRef("sources", input.sourcesDirKey()),
                    new ArtifactRef("manifest", input.manifestKey())));
}
```

Use equivalent results for parse, manifest facts, taint, misconfig, and report:

```java
return StepResult.completed(
        "parse",
        "Parsed sources and wrote AST index.",
        Map.of("indexFileCount", countRegularFiles(astIndexDir)),
        List.of(new ArtifactRef("ast-index", input.astIndexDirKey())));
```

```java
return StepResult.completed(
        "manifest-facts",
        "Extracted manifest facts.",
        Map.of("factsWritten", Files.exists(factsJson)),
        List.of(new ArtifactRef("facts", input.factsKey())));
```

```java
return taintBatchResult(input.rules());
```

```java
return analyzerResult(
        "manifest-misconfig",
        "manifest misconfiguration analysis",
        findingsJson,
        input.findingsKey());
```

```java
return StepResult.completed(
        "report",
        "Generated HTML and SARIF reports.",
        Map.of(
                "htmlWritten", Files.exists(html),
                "sarifWritten", Files.exists(sarif)),
        List.of(
                new ArtifactRef("html", input.htmlKey()),
                new ArtifactRef("sarif", input.sarifKey())));
```

- [ ] **Step 4: Run activity tests**

```bash
./gradlew :orchestrator:test --tests 'com.oversecured.sast.orchestrator.PipelineActivitiesImplTest'
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/src/main/java/com/oversecured/sast/orchestrator/activities/PipelineActivitiesImpl.java \
        orchestrator/src/test/java/com/oversecured/sast/orchestrator/PipelineActivitiesImplTest.java
git commit -m "feat(orchestrator): report per-step metrics and finding counts"
```

---

## Task 5: Add Workflow Query And Status Updates

**Files:**
- Modify: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/workflow/AnalyzeApkWorkflow.java`
- Modify: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/workflow/AnalyzeApkWorkflowImpl.java`
- Test: `orchestrator/src/test/java/com/oversecured/sast/orchestrator/AnalyzeApkWorkflowTest.java`

- [ ] **Step 1: Write failing workflow status query test**

Add test:

```java
@Test
void workflowStatusQueryShowsCompletedNodesWithDurationsAndFindingCounts() {
    RecordingActivities activities = new RecordingActivities(false);
    AnalyzeApkWorkflow workflow = newWorkflow(activities);

    AnalysisResult result = workflow.analyze(
            new AnalyzeApkRequest("/tmp/ovaa.apk",
                    AnalysisPlan.forRules("status-1", List.of("webview"))));

    RunStatus status = workflow.getStatus();

    assertThat(result.htmlReportKey()).isEqualTo("runs/status-1/report.html");
    assertThat(status.runId()).isEqualTo("status-1");
    assertThat(status.state()).isEqualTo(StepState.COMPLETED);
    assertThat(status.nodes()).extracting(NodeStatus::id).contains(
            "decompile",
            "parse",
            "manifest-facts",
            "taint",
            "manifest-misconfig",
            "report");
    NodeStatus taint = status.nodes().stream()
            .filter(node -> node.id().equals("taint"))
            .findFirst()
            .orElseThrow();
    assertThat(taint.state()).isEqualTo(StepState.COMPLETED);
    assertThat(taint.findingCount()).isZero();
    assertThat(taint.startedAt()).isNotNull();
    assertThat(taint.finishedAt()).isNotNull();
    assertThat(taint.durationMs()).isNotNull();
}
```

Add imports:

```java
import com.oversecured.sast.orchestrator.status.NodeStatus;
import com.oversecured.sast.orchestrator.status.RunStatus;
import com.oversecured.sast.orchestrator.status.StepState;
```

- [ ] **Step 2: Run test to verify it fails**

```bash
./gradlew :orchestrator:test --tests 'com.oversecured.sast.orchestrator.AnalyzeApkWorkflowTest.workflowStatusQueryShowsCompletedNodesWithDurationsAndFindingCounts'
```

Expected: compilation fails because `getStatus()` does not exist.

- [ ] **Step 3: Add query method to workflow interface**

Modify `AnalyzeApkWorkflow.java`:

```java
package com.oversecured.sast.orchestrator.workflow;

import com.oversecured.sast.orchestrator.AnalysisResult;
import com.oversecured.sast.orchestrator.AnalyzeApkRequest;
import com.oversecured.sast.orchestrator.status.RunStatus;
import io.temporal.workflow.QueryMethod;
import io.temporal.workflow.WorkflowInterface;
import io.temporal.workflow.WorkflowMethod;

@WorkflowInterface
public interface AnalyzeApkWorkflow {

    @WorkflowMethod
    AnalysisResult analyze(AnalyzeApkRequest request);

    @QueryMethod
    RunStatus getStatus();
}
```

- [ ] **Step 4: Implement status tracking in workflow**

In `AnalyzeApkWorkflowImpl`, add:

```java
private RunStatusBuilder status;

@Override
public RunStatus getStatus() {
    return status == null
            ? new RunStatus("unknown", StepState.QUEUED, "Queued.", null, null, null, List.of())
            : status.snapshot();
}
```

At the start of `analyze`:

```java
AnalysisPlan plan = request.plan();
status = new RunStatusBuilder(
        plan.runId(),
        nodeDefinitions(plan),
        () -> Instant.ofEpochMilli(Workflow.currentTimeMillis()));
```

Add node definitions:

```java
private static List<RunStatusBuilder.NodeDefinition> nodeDefinitions(AnalysisPlan plan) {
    List<RunStatusBuilder.NodeDefinition> nodes = new ArrayList<>();
    nodes.add(new RunStatusBuilder.NodeDefinition("decompile", "Decompile APK", "step"));
    nodes.add(new RunStatusBuilder.NodeDefinition("parse", "Parse Sources", "step"));
    nodes.add(new RunStatusBuilder.NodeDefinition("manifest-facts", "Manifest Facts", "step"));
    nodes.add(new RunStatusBuilder.NodeDefinition("taint", "Taint Analysis", "analyzer"));
    nodes.add(new RunStatusBuilder.NodeDefinition("manifest-misconfig", "Manifest Misconfig", "analyzer"));
    nodes.add(new RunStatusBuilder.NodeDefinition("report", "Report", "step"));
    return nodes;
}
```

Wrap each activity call:

```java
status.markRunning("decompile", "Decompiling APK.");
StepResult decompile = activities.decompile(new DecompileActivityInput(
        request.apkPath(),
        plan.keys().sourcesDirKey(),
        plan.keys().manifestKey()));
status.markCompleted(decompile);
String sourcesDirKey = plan.keys().sourcesDirKey();
```

For async branches, mark running before `Async.function`, and mark completed after `Promise.get()` returns:

```java
status.markRunning("parse", "Parsing source files.");
Promise<StepResult> astIndex = Async.function(activities::parseSources, new ParseActivityInput(
        sourcesDirKey,
        plan.keys().astIndexDirKey()));

status.markRunning("manifest-facts", "Extracting manifest facts.");
Promise<StepResult> facts = Async.function(activities::extractManifestFacts, new ManifestFactsActivityInput(
        plan.keys().manifestKey(),
        plan.keys().factsKey()));

StepResult parseResult = astIndex.get();
status.markCompleted(parseResult);
StepResult factsResult = facts.get();
status.markCompleted(factsResult);
```

Use known artifact keys from the plan instead of relying on activity return strings.

For the analyzer phase, keep only two concurrent analyzer branches: one batched taint activity and one manifest-misconfig activity.

```java
List<TaintBatchActivityInput.Rule> taintRules = plan.taintAnalyses().stream()
        .map(taint -> new TaintBatchActivityInput.Rule(
                taint.name(),
                taint.rulePath(),
                taint.findingsKey()))
        .toList();

status.markRunning("taint", "Running taint analysis for " + taintRules.size() + " rules.");
Promise<StepResult> taint = Async.function(
        activities::runTaintBatch,
        new TaintBatchActivityInput(astIndexDirKey, factsKey, taintRules));

status.markRunning("manifest-misconfig", "Running manifest misconfiguration checks.");
Promise<StepResult> misconfig = Async.function(
        activities::runManifestMisconfig,
        new MisconfigActivityInput(
                plan.manifestMisconfig().name(),
                factsKey,
                plan.manifestMisconfig().rulePath(),
                plan.manifestMisconfig().findingsKey()));

status.markCompleted(taint.get());
status.markCompleted(misconfig.get());
```

- [ ] **Step 5: Add failure conversion**

Wrap the body of `analyze` in:

```java
try {
    return runAnalyze(request);
} catch (RuntimeException e) {
    markCurrentFailure(e);
    throw e;
}
```

Track the most recent running node id:

```java
private String currentNodeId;

private void running(String nodeId, String message) {
    currentNodeId = nodeId;
    status.markRunning(nodeId, message);
}

private void markCurrentFailure(RuntimeException e) {
    if (status == null || currentNodeId == null) {
        return;
    }
    String message = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
    String kind = "UNKNOWN";
    if (e instanceof com.oversecured.sast.common.PipelineException pipelineException) {
        kind = pipelineException.kind().name();
    }
    status.markFailed(currentNodeId, "Step failed: " + message, new StepError(kind, message));
}
```

If failures in fan-out branches need exact node attribution, add a helper per promise that catches activity failure after `get()` and marks the node id known for that promise.

- [ ] **Step 6: Run workflow tests**

```bash
./gradlew :orchestrator:test --tests 'com.oversecured.sast.orchestrator.AnalyzeApkWorkflowTest'
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/src/main/java/com/oversecured/sast/orchestrator/workflow/AnalyzeApkWorkflow.java \
        orchestrator/src/main/java/com/oversecured/sast/orchestrator/workflow/AnalyzeApkWorkflowImpl.java \
        orchestrator/src/test/java/com/oversecured/sast/orchestrator/AnalyzeApkWorkflowTest.java
git commit -m "feat(orchestrator): expose workflow status query"
```

---

## Task 6: Add UI Database Schema

**Files:**
- Create: `ui/src/server/migrations/001_init.sql`
- Create: `ui/src/server/migrations/README.md`

- [ ] **Step 1: Create migration file**

Create `ui/src/server/migrations/001_init.sql`:

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE runs (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    workflow_id TEXT NOT NULL UNIQUE,
    apk_filename TEXT NOT NULL,
    apk_sha256 TEXT NOT NULL,
    apk_size_bytes BIGINT NOT NULL,
    artifact_root TEXT NOT NULL,
    status TEXT NOT NULL,
    message TEXT NOT NULL,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    duration_ms BIGINT,
    report_html_key TEXT,
    report_sarif_key TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE run_nodes (
    run_id UUID NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    node_id TEXT NOT NULL,
    label TEXT NOT NULL,
    kind TEXT NOT NULL,
    state TEXT NOT NULL,
    message TEXT NOT NULL,
    queued_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    duration_ms BIGINT,
    finding_count INTEGER NOT NULL DEFAULT 0,
    severity_counts JSONB NOT NULL DEFAULT '{}'::jsonb,
    metrics JSONB NOT NULL DEFAULT '{}'::jsonb,
    diagnostics JSONB NOT NULL DEFAULT '[]'::jsonb,
    artifacts JSONB NOT NULL DEFAULT '[]'::jsonb,
    error JSONB,
    findings_keys JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (run_id, node_id)
);

CREATE TABLE findings (
    id UUID PRIMARY KEY,
    run_id UUID NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    node_id TEXT NOT NULL,
    analyzer TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    vulnerability_class TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    cwe TEXT,
    owasp_mobile TEXT,
    source_file TEXT,
    source_line INTEGER,
    sink_file TEXT,
    sink_line INTEGER,
    raw_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX findings_run_id_idx ON findings(run_id);
CREATE INDEX findings_run_severity_idx ON findings(run_id, severity);
CREATE INDEX run_nodes_run_state_idx ON run_nodes(run_id, state);
```

- [ ] **Step 2: Create migrations README**

Create `ui/src/server/migrations/README.md`:

```markdown
# UI Database Migrations

The UI database stores user-owned scan metadata, latest Temporal status snapshots, graph node telemetry, and ingested findings.

Temporal remains the execution source of truth for active runs. The UI backend polls Temporal and upserts `runs` and `run_nodes`. Full finding rows are ingested from shared-volume `findings-*.json` artifacts after analyzer nodes complete.
```

- [ ] **Step 3: Commit**

```bash
git add ui/src/server/migrations/001_init.sql ui/src/server/migrations/README.md
git commit -m "feat(ui): add run status database schema"
```

---

## Task 7: Add UI Backend API Contract

**Files:**
- Create: `ui/src/server/routes/runs.ts`
- Create: `ui/src/server/services/status-sync.ts`
- Create: `ui/src/server/services/artifacts.ts`
- Create: `ui/src/server/temporal.ts`

- [ ] **Step 1: Implement endpoint contract**

Expose these routes:

```text
POST   /api/runs
GET    /api/runs
GET    /api/runs/:id
GET    /api/runs/:id/nodes
GET    /api/runs/:id/findings
GET    /api/runs/:id/reports/html
GET    /api/runs/:id/reports/sarif
```

Expected response for `GET /api/runs/:id`:

```json
{
  "id": "1d246e7e-bf69-4a8b-83c8-68df98319875",
  "workflowId": "android-sast-1d246e7e-bf69-4a8b-83c8-68df98319875",
  "apkFilename": "app-release.apk",
  "status": "RUNNING",
  "message": "Scan is running.",
  "startedAt": "2026-06-28T10:00:00Z",
  "finishedAt": null,
  "durationMs": null,
  "nodes": []
}
```

Expected response for `GET /api/runs/:id/nodes`:

```json
[
  {
    "id": "decompile",
    "label": "Decompile APK",
    "kind": "step",
    "state": "COMPLETED",
    "message": "Decompiled APK into 842 source files.",
    "startedAt": "2026-06-28T10:00:00Z",
    "finishedAt": "2026-06-28T10:00:03Z",
    "durationMs": 3000,
    "findingCount": 0,
    "severityCounts": {},
    "metrics": {"sourceFileCount": 842},
    "diagnostics": [],
    "artifacts": [{"type": "sources", "key": "runs/run-1/sources"}],
    "error": null
  }
]
```

- [ ] **Step 2: Implement Temporal polling bridge behavior**

`status-sync.ts` must:

```text
1. Find active DB runs where status is QUEUED or RUNNING.
2. Query Temporal workflow getStatus().
3. Upsert runs row from RunStatus.
4. Upsert one run_nodes row per NodeStatus.
5. For any analyzer node with state COMPLETED and findings keys not yet ingested, read each findings JSON artifact and insert findings rows.
6. Repeat every 1 second in the UI backend process.
```

Keep failures in the sync loop non-fatal:

```text
If Temporal query fails for one run, log the workflow id and continue with the next run.
If findings ingestion fails for one node, store the node status and retry ingestion on the next poll.
```

- [ ] **Step 3: Commit**

```bash
git add ui/src/server/routes/runs.ts \
        ui/src/server/services/status-sync.ts \
        ui/src/server/services/artifacts.ts \
        ui/src/server/temporal.ts
git commit -m "feat(ui): add run status API contract"
```

---

## Task 8: Add Pipeline Graph Frontend

**Files:**
- Create: `ui/src/client/components/PipelineGraph.tsx`
- Create: `ui/src/client/components/RunDetail.tsx`
- Create: `ui/src/client/components/FindingTable.tsx`

- [ ] **Step 1: Implement graph data mapping**

Graph nodes map directly from API node status:

```ts
type GraphNodeState = 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED';

type RunNode = {
  id: string;
  label: string;
  kind: string;
  state: GraphNodeState;
  message: string;
  startedAt: string | null;
  finishedAt: string | null;
  durationMs: number | null;
  findingCount: number;
  severityCounts: Record<string, number>;
  metrics: Record<string, unknown>;
  diagnostics: Array<{ where: string; detail: string }>;
  artifacts: Array<{ type: string; key: string }>;
  error: { kind: string; message: string } | null;
};
```

Color states:

```text
QUEUED    gray
RUNNING   blue with spinner
COMPLETED green
FAILED    red
```

Node content:

```text
label
state badge
message
duration if available
finding count if > 0 or analyzer kind
error message if failed
```

- [ ] **Step 2: Implement polling**

`RunDetail.tsx` polls:

```text
GET /api/runs/:id
GET /api/runs/:id/nodes
GET /api/runs/:id/findings
```

Polling interval:

```text
1000ms while status is QUEUED or RUNNING
stop polling when status is COMPLETED or FAILED
```

- [ ] **Step 3: Commit**

```bash
git add ui/src/client/components/PipelineGraph.tsx \
        ui/src/client/components/RunDetail.tsx \
        ui/src/client/components/FindingTable.tsx
git commit -m "feat(ui): render scan pipeline graph"
```

---

## Task 9: Wire Docker Compose For UI And DB

**Files:**
- Modify: `docker-compose.yml`
- Create: `ui/Dockerfile`
- Create: `ui/.dockerignore`

- [ ] **Step 1: Add UI database service**

Add a separate database from Temporal Postgres:

```yaml
  ui-postgres:
    image: postgres:16
    environment:
      POSTGRES_USER: ui
      POSTGRES_PASSWORD: ui
      POSTGRES_DB: ui
    volumes:
      - ui-postgres:/var/lib/postgresql/data
```

Add volume:

```yaml
  ui-postgres:
```

- [ ] **Step 2: Add UI service**

```yaml
  ui:
    build:
      context: .
      dockerfile: ui/Dockerfile
    depends_on:
      - temporal
      - ui-postgres
    environment:
      DATABASE_URL: postgres://ui:ui@ui-postgres:5432/ui
      TEMPORAL_ADDRESS: temporal:7233
      ARTIFACT_ROOT: /workspace/artifacts
    ports:
      - "3000:3000"
    volumes:
      - ./artifacts:/workspace/artifacts
```

Keep `worker` without public ports.

- [ ] **Step 3: Commit**

```bash
git add docker-compose.yml ui/Dockerfile ui/.dockerignore
git commit -m "chore(compose): add ui app and metadata database"
```

---

## Task 10: End-To-End Verification

**Files:**
- Modify: `README.md`
- Create: `docs/ui-run-status.md`

- [ ] **Step 1: Run Java verification**

```bash
./gradlew test
```

Expected: all Java tests pass.

- [ ] **Step 2: Run compose verification**

```bash
docker compose up --build
```

Expected:

```text
temporal starts
worker connects to temporal
ui connects to temporal and ui-postgres
http://localhost:3000 loads
```

- [ ] **Step 3: Submit a known test APK**

Use the UI upload form. Expected:

```text
run row appears
graph nodes transition queued -> running -> completed
decompile node shows source file count and duration
parse node shows AST index metrics and duration
manifest node shows readable success
taint node shows aggregate finding counts after completion, with per-rule summaries in its metrics
report node exposes HTML and SARIF links
```

- [ ] **Step 4: Submit a bad APK**

Upload an empty file named `bad.apk`. Expected:

```text
decompile node becomes FAILED
node message contains a readable APK validation error
run status becomes FAILED
downstream nodes remain QUEUED
browser shows no stack trace
```

- [ ] **Step 5: Document run status architecture**

Create `docs/ui-run-status.md`:

```markdown
# UI Run Status

The UI backend starts Temporal workflows and polls `AnalyzeApkWorkflow.getStatus()` while a run is active. Temporal owns execution state. The UI database stores the latest read model for run lists, graph rendering, and finding filters.

The pipeline worker never writes directly to the UI database. Analyzer activities write `findings-*.json` artifacts to the shared volume and return compact counts and artifact keys through Temporal. The UI backend ingests full findings from those artifact keys.
```

- [ ] **Step 6: Commit**

```bash
git add README.md docs/ui-run-status.md
git commit -m "docs: describe ui run status flow"
```

---

## Self-Review

- Spec coverage:
  - Every step reports readable status: Tasks 1, 4, and 5.
  - Every step records timestamps and duration: Task 2 and Task 5.
  - Errors report through same UI contract: Task 1 and Task 5.
  - Finding counts from Temporal node status: Task 4 and Task 5.
  - DB stores run list, graph node snapshots, and full findings: Task 6 and Task 7.
  - UI graph renders node states and findings: Task 8.
  - Separate UI container and private worker: Task 9.

- Placeholder scan:
  - The plan avoids placeholder markers.
  - UI backend route internals are described as contracts because the UI app does not exist yet; before implementation, choose the exact TypeScript server stack and pin dependencies in `ui/package.json`.

- Type consistency:
  - `StepResult`, `NodeStatus`, and DB `run_nodes` use the same field names conceptually.
  - Java enum states map directly to DB/frontend strings: `QUEUED`, `RUNNING`, `COMPLETED`, `FAILED`.
