# Orchestrator Implementation Plan

**Shared conventions:** [Shared Contracts and Naming Conventions](../reference/2026-06-27-shared-contracts-and-conventions.md)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `:orchestrator` — a Temporal Java SDK workflow and worker that runs the Android SAST DAG `decompile -> {parse || manifest-facts} -> {taint webview || taint pathtraversal || manifest-misconfig} -> reporter`, passing only artifact keys/paths between independently runnable step apps.

**Architecture:** The module contains Temporal workflow interfaces/implementations, activity interfaces/implementations, a workflow starter CLI, and local docker-compose runtime wiring. The workflow is deterministic and contains no analysis, parsing, rule loading, decompilation, or rendering logic; activities call step module library APIs and pass stable artifact keys. `AnalysisPlan` is the single config object for rule files, output artifact keys, and report artifact keys, so adding another analyzer branch is a data change rather than workflow code change.

**Tech Stack:** Java 17, Gradle Groovy multi-module, Temporal Java SDK `1.36.0`, Temporal testing `1.36.0`, JUnit 5 + AssertJ, picocli, Docker Compose, PostgreSQL-backed local Temporal Server, Temporal UI, Java worker container, optional MinIO/local-volume artifact storage.

## Global Constraints

- **Module:** `orchestrator`, Gradle path `:orchestrator`.
- **Package root:** `com.oversecured.sast.orchestrator`.
- **Role boundary:** orchestration only. No taint propagation, manifest parsing, rule parsing, jadx handling, AST traversal, findings merging policy, HTML rendering, or SARIF rendering lives here.
- **Step execution:** activities call library APIs exposed by step modules. CLI commands remain independently runnable for debugging, but workflow activities should not parse another process's stdout as a contract.
- **Artifact contract:** workflow and activities pass artifact keys and local paths. Logical artifact names follow the shared contract:
  - `sources/`
  - `sources/AndroidManifest.xml`
  - `ast-index/`
  - `facts.json`
  - `findings-webview.json`
  - `findings-pathtraversal.json`
  - `findings-misconfig.json`
  - `report.html`
  - `report.sarif`
- **Run prefix:** physical keys are prefixed with `runs/<runId>/`, for example `runs/ovaa-001/sources` and `runs/ovaa-001/report.sarif`.
- **Workflow determinism:** workflow code may construct records, strings, and Temporal promises only. No filesystem access, network access, random UUID generation, wall-clock time, process execution, static mutable state, or direct step library calls in workflow code.
- **Temporal task queue:** one default queue named `android-sast-pipeline`.
- **Retry policy:** every activity uses the same retry policy unless a later production hardening change proves a different policy is needed: initial interval 1 second, backoff coefficient 2.0, maximum interval 30 seconds, maximum attempts 3.
- **Idempotency:** every activity writes deterministic output paths from the input plan and may overwrite its own output artifact on retry. Activities must not append to existing artifacts or generate fresh output names inside retries.
- **Build versions:** the root `build.gradle` owns versions. This plan adds `temporalVersion = '1.36.0'` to the root `ext` block if absent and references `rootProject.ext.temporalVersion` from `orchestrator/build.gradle`.
- **Application plugin:** `:orchestrator` is runnable and exposes a starter CLI plus a worker main class.
- **Testing:** unit tests use Temporal `TestWorkflowEnvironment` and real in-memory activity implementations, not Mockito, so fan-out/fan-in ordering is tested through Temporal execution.
- **Docker compose ownership:** this plan owns root `docker-compose.yml` and `orchestrator/Dockerfile` because the compose file exists to run Temporal plus the orchestrator worker. It must preserve any existing non-orchestrator services if the file already exists at implementation time.

### Temporal API notes used by this plan

- `@WorkflowInterface` and `@WorkflowMethod` define the workflow contract.
- `@ActivityInterface` and `@ActivityMethod` define the activity contract.
- `Workflow.newActivityStub(...)` creates activity stubs inside workflow code.
- `Async.function(...)`, `Promise`, and `Promise.allOf(...)` implement fan-out/fan-in in workflow code.
- `WorkerFactory`, `Worker`, and `WorkflowClient` register workflow/activity implementations and start workers.
- `temporal-testing` provides `TestWorkflowEnvironment` for deterministic workflow tests.

### Step library API expectations

The orchestrator consumes these step library entry points. If a step plan lands with a different public class name, add a tiny adapter inside that step module and keep the orchestrator-facing method shape below stable.

```java
// apps/decompiler, already specified by the decompiler plan
new com.oversecured.sast.decompiler.Decompiler()
    .decompile(java.nio.file.Path apk, java.nio.file.Path outDir);

// apps/parser, already specified by the parser plan
com.oversecured.sast.parser.AstIndex
    .build(java.nio.file.Path sourcesDir)
    .save(java.nio.file.Path astIndexDir);

// apps/manifest-facts
new com.oversecured.sast.manifestfacts.ManifestFactsApp()
    .extract(java.nio.file.Path manifestXml, java.nio.file.Path factsJson);

// apps/taint
new com.oversecured.sast.taint.TaintAnalyzer()
    .run(java.nio.file.Path astIndexDir, java.nio.file.Path factsJson, java.nio.file.Path ruleYaml, java.nio.file.Path findingsJson);

// apps/manifest-misconfig
new com.oversecured.sast.misconfig.MisconfigApp()
    .analyze(java.nio.file.Path factsJson, java.nio.file.Path ruleYaml, java.nio.file.Path findingsJson);

// apps/reporter, already specified by the reporter plan
new com.oversecured.sast.reporter.FindingsMerger().merge(java.util.List<java.nio.file.Path> findingsFiles);
new com.oversecured.sast.reporter.HtmlReportRenderer().render(findings);
new com.oversecured.sast.reporter.SarifReportWriter().toSarifJson(findings);
```

---

## File Structure

```
challenge/
├── build.gradle                                      # Modify: add temporalVersion to root ext if absent
├── docker-compose.yml                                # Create: Temporal/Postgres/UI/worker/local-artifacts/optional MinIO
└── orchestrator/
    ├── build.gradle                                  # application + Temporal + step module dependencies
    ├── Dockerfile                                    # worker container image
    └── src/
        ├── main/java/com/oversecured/sast/orchestrator/
        │   ├── AnalysisPlan.java                     # run id, rule config, output artifact keys
        │   ├── AnalyzeApkRequest.java                # workflow request: apk path/key + AnalysisPlan
        │   ├── AnalysisResult.java                   # workflow result: final report artifacts
        │   ├── ArtifactKeys.java                     # deterministic run-prefixed artifact key helper
        │   ├── TaskQueues.java                       # Temporal task queue constants
        │   ├── workflow/
        │   │   ├── AnalyzeApkWorkflow.java           # Temporal workflow interface
        │   │   └── AnalyzeApkWorkflowImpl.java       # DAG: decompile -> parallel prereqs -> fan-out -> reporter
        │   ├── activities/
        │   │   ├── PipelineActivities.java           # Temporal activity interface
        │   │   ├── PipelineActivitiesImpl.java       # calls step library APIs, resolves keys to paths
        │   │   ├── ActivityPathResolver.java         # artifact key -> local Path, path traversal guard
        │   │   ├── DecompileActivityInput.java
        │   │   ├── ParseActivityInput.java
        │   │   ├── ManifestFactsActivityInput.java
        │   │   ├── TaintActivityInput.java
        │   │   ├── MisconfigActivityInput.java
        │   │   ├── ReportActivityInput.java
        │   │   └── ReportArtifacts.java
        │   └── cli/
        │       ├── WorkerMain.java                   # registers workflow + activities on Temporal task queue
        │       └── StartAnalysisCommand.java         # picocli workflow starter
        └── test/java/com/oversecured/sast/orchestrator/
            ├── AnalysisPlanTest.java                 # default config and artifact key wiring
            ├── ActivityPathResolverTest.java          # local path resolution and key safety
            ├── AnalyzeApkWorkflowTest.java            # DAG order, parallel branches, fan-in
            ├── PipelineActivitiesImplTest.java        # activity -> step library path wiring with test doubles
            └── StartAnalysisCommandTest.java          # CLI parses args and starts workflow with expected options
```

---

### Task 1: Gradle module, Temporal dependencies, and immutable plan records

**Files:**
- Modify: `build.gradle`
- Modify: `orchestrator/build.gradle`
- Create: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/TaskQueues.java`
- Create: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/ArtifactKeys.java`
- Create: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/AnalysisPlan.java`
- Create: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/AnalyzeApkRequest.java`
- Create: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/AnalysisResult.java`
- Test: `orchestrator/src/test/java/com/oversecured/sast/orchestrator/AnalysisPlanTest.java`

**Interfaces:**
- Consumes: root Gradle build from `2026-06-27-common.md`.
- Produces:
  - `TaskQueues.DEFAULT = "android-sast-pipeline"`
  - `ArtifactKeys.forRun(String runId)`
  - `AnalysisPlan.defaultPlan(String runId)`
  - `AnalyzeApkRequest(String apkPath, AnalysisPlan plan)`
  - `AnalysisResult(String htmlReportKey, String sarifReportKey)`

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/src/test/java/com/oversecured/sast/orchestrator/AnalysisPlanTest.java`:

```java
package com.oversecured.sast.orchestrator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class AnalysisPlanTest {

    @Test
    void defaultPlanDefinesAllRequiredBranchesAndOutputs() {
        AnalysisPlan plan = AnalysisPlan.defaultPlan("ovaa-001");

        assertThat(plan.runId()).isEqualTo("ovaa-001");
        assertThat(plan.keys().sourcesDirKey()).isEqualTo("runs/ovaa-001/sources");
        assertThat(plan.keys().manifestKey()).isEqualTo("runs/ovaa-001/sources/AndroidManifest.xml");
        assertThat(plan.keys().astIndexDirKey()).isEqualTo("runs/ovaa-001/ast-index");
        assertThat(plan.keys().factsKey()).isEqualTo("runs/ovaa-001/facts.json");

        assertThat(plan.taintAnalyses())
                .extracting(AnalysisPlan.TaintAnalysis::name)
                .containsExactly("webview", "pathtraversal");
        assertThat(plan.taintAnalyses())
                .extracting(AnalysisPlan.TaintAnalysis::rulePath)
                .containsExactly("rules/webview.yaml", "rules/pathtraversal.yaml");
        assertThat(plan.taintAnalyses())
                .extracting(AnalysisPlan.TaintAnalysis::findingsKey)
                .containsExactly(
                        "runs/ovaa-001/findings-webview.json",
                        "runs/ovaa-001/findings-pathtraversal.json");

        assertThat(plan.manifestMisconfig().rulePath()).isEqualTo("rules/misconfig.yaml");
        assertThat(plan.manifestMisconfig().findingsKey()).isEqualTo("runs/ovaa-001/findings-misconfig.json");
        assertThat(plan.report().htmlKey()).isEqualTo("runs/ovaa-001/report.html");
        assertThat(plan.report().sarifKey()).isEqualTo("runs/ovaa-001/report.sarif");
    }

    @Test
    void allFindingKeysReturnInReporterInputOrder() {
        AnalysisPlan plan = AnalysisPlan.defaultPlan("run-7");

        assertThat(plan.findingsKeysForReporter())
                .containsExactly(
                        "runs/run-7/findings-webview.json",
                        "runs/run-7/findings-pathtraversal.json",
                        "runs/run-7/findings-misconfig.json");
    }

    @Test
    void runIdMustBeAStablePathSegment() {
        assertThatThrownBy(() -> AnalysisPlan.defaultPlan("../escape"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("runId");

        assertThatThrownBy(() -> AnalysisPlan.defaultPlan("contains space"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("runId");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./gradlew :orchestrator:test --tests 'com.oversecured.sast.orchestrator.AnalysisPlanTest'`

Expected: FAIL with compilation errors for missing `AnalysisPlan` and `ArtifactKeys`.

- [ ] **Step 3: Add Temporal version and orchestrator dependencies**

Modify the root `build.gradle` `ext` block by adding exactly this line if it is absent:

```groovy
temporalVersion = '1.36.0'
```

Replace `orchestrator/build.gradle` with:

```groovy
plugins {
    id 'application'
}

dependencies {
    implementation project(':common')
    implementation project(':apps:decompiler')
    implementation project(':apps:parser')
    implementation project(':apps:manifest-facts')
    implementation project(':apps:taint')
    implementation project(':apps:manifest-misconfig')
    implementation project(':apps:reporter')

    implementation "io.temporal:temporal-sdk:${rootProject.ext.temporalVersion}"
    implementation "info.picocli:picocli:${rootProject.ext.picocliVersion}"
    annotationProcessor "info.picocli:picocli-codegen:${rootProject.ext.picocliVersion}"

    testImplementation("io.temporal:temporal-testing:${rootProject.ext.temporalVersion}") {
        capabilities {
            requireCapability("io.temporal:temporal-testing-junit5")
        }
    }
}

application {
    mainClass = 'com.oversecured.sast.orchestrator.cli.WorkerMain'
}
```

- [ ] **Step 4: Write constants and records**

Create `orchestrator/src/main/java/com/oversecured/sast/orchestrator/TaskQueues.java`:

```java
package com.oversecured.sast.orchestrator;

public final class TaskQueues {
    public static final String DEFAULT = "android-sast-pipeline";

    private TaskQueues() {
    }
}
```

Create `orchestrator/src/main/java/com/oversecured/sast/orchestrator/ArtifactKeys.java`:

```java
package com.oversecured.sast.orchestrator;

import java.util.regex.Pattern;

public record ArtifactKeys(
        String runId,
        String rootKey,
        String sourcesDirKey,
        String manifestKey,
        String astIndexDirKey,
        String factsKey) {

    private static final Pattern RUN_ID = Pattern.compile("[A-Za-z0-9._-]+");

    public static ArtifactKeys forRun(String runId) {
        if (runId == null || !RUN_ID.matcher(runId).matches()) {
            throw new IllegalArgumentException("runId must match [A-Za-z0-9._-]+");
        }
        String root = "runs/" + runId;
        return new ArtifactKeys(
                runId,
                root,
                root + "/sources",
                root + "/sources/AndroidManifest.xml",
                root + "/ast-index",
                root + "/facts.json");
    }
}
```

Create `orchestrator/src/main/java/com/oversecured/sast/orchestrator/AnalysisPlan.java`:

```java
package com.oversecured.sast.orchestrator;

import java.util.ArrayList;
import java.util.List;

public record AnalysisPlan(
        String runId,
        ArtifactKeys keys,
        List<TaintAnalysis> taintAnalyses,
        ManifestMisconfigAnalysis manifestMisconfig,
        ReportConfig report) {

    public AnalysisPlan {
        taintAnalyses = List.copyOf(taintAnalyses);
    }

    public static AnalysisPlan defaultPlan(String runId) {
        ArtifactKeys keys = ArtifactKeys.forRun(runId);
        return new AnalysisPlan(
                runId,
                keys,
                List.of(
                        new TaintAnalysis(
                                "webview",
                                "rules/webview.yaml",
                                keys.rootKey() + "/findings-webview.json"),
                        new TaintAnalysis(
                                "pathtraversal",
                                "rules/pathtraversal.yaml",
                                keys.rootKey() + "/findings-pathtraversal.json")),
                new ManifestMisconfigAnalysis(
                        "manifest-misconfig",
                        "rules/misconfig.yaml",
                        keys.rootKey() + "/findings-misconfig.json"),
                new ReportConfig(
                        keys.rootKey() + "/report.html",
                        keys.rootKey() + "/report.sarif"));
    }

    public List<String> findingsKeysForReporter() {
        List<String> keys = new ArrayList<>();
        for (TaintAnalysis analysis : taintAnalyses) {
            keys.add(analysis.findingsKey());
        }
        keys.add(manifestMisconfig.findingsKey());
        return List.copyOf(keys);
    }

    public record TaintAnalysis(String name, String rulePath, String findingsKey) {
    }

    public record ManifestMisconfigAnalysis(String name, String rulePath, String findingsKey) {
    }

    public record ReportConfig(String htmlKey, String sarifKey) {
    }
}
```

Create `orchestrator/src/main/java/com/oversecured/sast/orchestrator/AnalyzeApkRequest.java`:

```java
package com.oversecured.sast.orchestrator;

public record AnalyzeApkRequest(String apkPath, AnalysisPlan plan) {
}
```

Create `orchestrator/src/main/java/com/oversecured/sast/orchestrator/AnalysisResult.java`:

```java
package com.oversecured.sast.orchestrator;

public record AnalysisResult(String htmlReportKey, String sarifReportKey) {
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `./gradlew :orchestrator:test --tests 'com.oversecured.sast.orchestrator.AnalysisPlanTest'`

Expected: PASS. `AnalysisPlanTest` has 3 passing tests.

- [ ] **Step 6: Commit**

```bash
git add build.gradle orchestrator/build.gradle orchestrator/src/main/java/com/oversecured/sast/orchestrator orchestrator/src/test/java/com/oversecured/sast/orchestrator/AnalysisPlanTest.java
git commit -m "feat(orchestrator): add Temporal dependencies and analysis plan artifact keys"
```

---

### Task 2: Activity contracts and local artifact path resolution

**Files:**
- Create: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/activities/PipelineActivities.java`
- Create: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/activities/ActivityPathResolver.java`
- Create: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/activities/DecompileActivityInput.java`
- Create: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/activities/ParseActivityInput.java`
- Create: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/activities/ManifestFactsActivityInput.java`
- Create: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/activities/TaintActivityInput.java`
- Create: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/activities/MisconfigActivityInput.java`
- Create: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/activities/ReportActivityInput.java`
- Create: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/activities/ReportArtifacts.java`
- Test: `orchestrator/src/test/java/com/oversecured/sast/orchestrator/ActivityPathResolverTest.java`

**Interfaces:**
- Consumes: `AnalysisPlan`, `ArtifactKeys`.
- Produces: one Temporal activity method per pipeline step, all returning deterministic artifact keys.

- [ ] **Step 1: Write the failing test**

Create `orchestrator/src/test/java/com/oversecured/sast/orchestrator/ActivityPathResolverTest.java`:

```java
package com.oversecured.sast.orchestrator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.oversecured.sast.orchestrator.activities.ActivityPathResolver;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ActivityPathResolverTest {

    @Test
    void resolvesArtifactKeysUnderRoot(@TempDir Path root) {
        ActivityPathResolver resolver = new ActivityPathResolver(root);

        assertThat(resolver.resolveArtifactKey("runs/r1/report.html"))
                .isEqualTo(root.resolve("runs/r1/report.html").toAbsolutePath().normalize());
    }

    @Test
    void rejectsAbsoluteKeys(@TempDir Path root) {
        ActivityPathResolver resolver = new ActivityPathResolver(root);

        assertThatThrownBy(() -> resolver.resolveArtifactKey("/tmp/report.html"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("artifact key");
    }

    @Test
    void rejectsParentDirectoryTraversal(@TempDir Path root) {
        ActivityPathResolver resolver = new ActivityPathResolver(root);

        assertThatThrownBy(() -> resolver.resolveArtifactKey("runs/r1/../../escape.txt"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("artifact key");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./gradlew :orchestrator:test --tests 'com.oversecured.sast.orchestrator.ActivityPathResolverTest'`

Expected: FAIL with compilation error for missing `ActivityPathResolver`.

- [ ] **Step 3: Write activity input/output records**

Create `orchestrator/src/main/java/com/oversecured/sast/orchestrator/activities/DecompileActivityInput.java`:

```java
package com.oversecured.sast.orchestrator.activities;

public record DecompileActivityInput(String apkPath, String sourcesDirKey, String manifestKey) {
}
```

Create `orchestrator/src/main/java/com/oversecured/sast/orchestrator/activities/ParseActivityInput.java`:

```java
package com.oversecured.sast.orchestrator.activities;

public record ParseActivityInput(String sourcesDirKey, String astIndexDirKey) {
}
```

Create `orchestrator/src/main/java/com/oversecured/sast/orchestrator/activities/ManifestFactsActivityInput.java`:

```java
package com.oversecured.sast.orchestrator.activities;

public record ManifestFactsActivityInput(String manifestKey, String factsKey) {
}
```

Create `orchestrator/src/main/java/com/oversecured/sast/orchestrator/activities/TaintActivityInput.java`:

```java
package com.oversecured.sast.orchestrator.activities;

public record TaintActivityInput(
        String analysisName,
        String astIndexDirKey,
        String factsKey,
        String rulePath,
        String findingsKey) {
}
```

Create `orchestrator/src/main/java/com/oversecured/sast/orchestrator/activities/MisconfigActivityInput.java`:

```java
package com.oversecured.sast.orchestrator.activities;

public record MisconfigActivityInput(
        String analysisName,
        String factsKey,
        String rulePath,
        String findingsKey) {
}
```

Create `orchestrator/src/main/java/com/oversecured/sast/orchestrator/activities/ReportActivityInput.java`:

```java
package com.oversecured.sast.orchestrator.activities;

import java.util.List;

public record ReportActivityInput(List<String> findingsKeys, String htmlKey, String sarifKey) {
    public ReportActivityInput {
        findingsKeys = List.copyOf(findingsKeys);
    }
}
```

Create `orchestrator/src/main/java/com/oversecured/sast/orchestrator/activities/ReportArtifacts.java`:

```java
package com.oversecured.sast.orchestrator.activities;

public record ReportArtifacts(String htmlKey, String sarifKey) {
}
```

- [ ] **Step 4: Write `PipelineActivities.java`**

Create `orchestrator/src/main/java/com/oversecured/sast/orchestrator/activities/PipelineActivities.java`:

```java
package com.oversecured.sast.orchestrator.activities;

import io.temporal.activity.ActivityInterface;
import io.temporal.activity.ActivityMethod;

@ActivityInterface
public interface PipelineActivities {

    @ActivityMethod
    String decompile(DecompileActivityInput input);

    @ActivityMethod
    String parseSources(ParseActivityInput input);

    @ActivityMethod
    String extractManifestFacts(ManifestFactsActivityInput input);

    @ActivityMethod
    String runTaint(TaintActivityInput input);

    @ActivityMethod
    String runManifestMisconfig(MisconfigActivityInput input);

    @ActivityMethod
    ReportArtifacts report(ReportActivityInput input);
}
```

- [ ] **Step 5: Write `ActivityPathResolver.java`**

Create `orchestrator/src/main/java/com/oversecured/sast/orchestrator/activities/ActivityPathResolver.java`:

```java
package com.oversecured.sast.orchestrator.activities;

import java.nio.file.Path;

public final class ActivityPathResolver {

    private final Path artifactRoot;

    public ActivityPathResolver(Path artifactRoot) {
        this.artifactRoot = artifactRoot.toAbsolutePath().normalize();
    }

    public Path resolveArtifactKey(String key) {
        if (key == null || key.isBlank()) {
            throw new IllegalArgumentException("artifact key must not be blank");
        }
        Path keyPath = Path.of(key);
        if (keyPath.isAbsolute()) {
            throw new IllegalArgumentException("artifact key must be relative: " + key);
        }
        Path resolved = artifactRoot.resolve(keyPath).toAbsolutePath().normalize();
        if (!resolved.startsWith(artifactRoot)) {
            throw new IllegalArgumentException("artifact key escapes artifact root: " + key);
        }
        return resolved;
    }

    public Path resolveInputPath(String path) {
        if (path == null || path.isBlank()) {
            throw new IllegalArgumentException("input path must not be blank");
        }
        return Path.of(path).toAbsolutePath().normalize();
    }
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `./gradlew :orchestrator:test --tests 'com.oversecured.sast.orchestrator.ActivityPathResolverTest'`

Expected: PASS. `ActivityPathResolverTest` has 3 passing tests.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/src/main/java/com/oversecured/sast/orchestrator/activities orchestrator/src/test/java/com/oversecured/sast/orchestrator/ActivityPathResolverTest.java
git commit -m "feat(orchestrator): define pipeline activities and artifact path resolver"
```

---

### Task 3: Temporal workflow DAG with decompile, parallel prerequisites, analyzer fan-out, and reporter fan-in

**Files:**
- Create: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/workflow/AnalyzeApkWorkflow.java`
- Create: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/workflow/AnalyzeApkWorkflowImpl.java`
- Test: `orchestrator/src/test/java/com/oversecured/sast/orchestrator/AnalyzeApkWorkflowTest.java`

**Interfaces:**
- Consumes: `PipelineActivities`, activity input records, `AnalyzeApkRequest`, `AnalysisPlan`.
- Produces: deterministic Temporal workflow:
  - `decompile`
  - `parseSources` and `extractManifestFacts` in parallel after decompile
  - `runTaint` for each `AnalysisPlan.TaintAnalysis` and `runManifestMisconfig` in parallel after both prerequisites
  - `report` after all analyzer findings exist

- [ ] **Step 1: Write the failing workflow tests**

Create `orchestrator/src/test/java/com/oversecured/sast/orchestrator/AnalyzeApkWorkflowTest.java`:

```java
package com.oversecured.sast.orchestrator;

import static org.assertj.core.api.Assertions.assertThat;

import com.oversecured.sast.orchestrator.activities.DecompileActivityInput;
import com.oversecured.sast.orchestrator.activities.ManifestFactsActivityInput;
import com.oversecured.sast.orchestrator.activities.MisconfigActivityInput;
import com.oversecured.sast.orchestrator.activities.ParseActivityInput;
import com.oversecured.sast.orchestrator.activities.PipelineActivities;
import com.oversecured.sast.orchestrator.activities.ReportActivityInput;
import com.oversecured.sast.orchestrator.activities.ReportArtifacts;
import com.oversecured.sast.orchestrator.activities.TaintActivityInput;
import com.oversecured.sast.orchestrator.workflow.AnalyzeApkWorkflow;
import com.oversecured.sast.orchestrator.workflow.AnalyzeApkWorkflowImpl;
import io.temporal.client.WorkflowClient;
import io.temporal.client.WorkflowOptions;
import io.temporal.testing.TestWorkflowEnvironment;
import io.temporal.worker.Worker;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class AnalyzeApkWorkflowTest {

    private TestWorkflowEnvironment testEnv;

    @AfterEach
    void closeTemporalEnvironment() {
        if (testEnv != null) {
            testEnv.close();
        }
    }

    @Test
    void workflowWiresDAGOrderAndArtifactKeys() {
        RecordingActivities activities = new RecordingActivities(false);
        AnalyzeApkWorkflow workflow = newWorkflow(activities);

        AnalysisResult result = workflow.analyze(
                new AnalyzeApkRequest("/tmp/ovaa.apk", AnalysisPlan.defaultPlan("run-1")));

        assertThat(result).isEqualTo(new AnalysisResult(
                "runs/run-1/report.html",
                "runs/run-1/report.sarif"));

        assertThat(activities.calls).containsExactly(
                "decompile:runs/run-1/sources",
                "parse:runs/run-1/ast-index",
                "manifest-facts:runs/run-1/facts.json",
                "taint:webview:runs/run-1/findings-webview.json",
                "taint:pathtraversal:runs/run-1/findings-pathtraversal.json",
                "misconfig:manifest-misconfig:runs/run-1/findings-misconfig.json",
                "report:runs/run-1/report.html:runs/run-1/report.sarif");

        assertThat(activities.reportInput.findingsKeys()).containsExactly(
                "runs/run-1/findings-webview.json",
                "runs/run-1/findings-pathtraversal.json",
                "runs/run-1/findings-misconfig.json");
    }

    @Test
    void workflowStartsPrerequisitesAndAnalyzersAsFanOutBranches() {
        RecordingActivities activities = new RecordingActivities(true);
        AnalyzeApkWorkflow workflow = newWorkflow(activities);

        AnalysisResult result = workflow.analyze(
                new AnalyzeApkRequest("/tmp/ovaa.apk", AnalysisPlan.defaultPlan("fanout-1")));

        assertThat(result.htmlReportKey()).isEqualTo("runs/fanout-1/report.html");
        assertThat(activities.parseAndFactsWereConcurrentlyStarted).isTrue();
        assertThat(activities.analyzersWereConcurrentlyStarted).isTrue();
    }

    private AnalyzeApkWorkflow newWorkflow(RecordingActivities activities) {
        testEnv = TestWorkflowEnvironment.newInstance();
        Worker worker = testEnv.newWorker(TaskQueues.DEFAULT);
        worker.registerWorkflowImplementationTypes(AnalyzeApkWorkflowImpl.class);
        worker.registerActivitiesImplementations(activities);
        testEnv.start();

        WorkflowClient client = testEnv.getWorkflowClient();
        return client.newWorkflowStub(
                AnalyzeApkWorkflow.class,
                WorkflowOptions.newBuilder()
                        .setWorkflowId("test-" + System.nanoTime())
                        .setTaskQueue(TaskQueues.DEFAULT)
                        .setWorkflowRunTimeout(Duration.ofMinutes(1))
                        .build());
    }

    private static final class RecordingActivities implements PipelineActivities {
        private final boolean requireConcurrentFanOut;
        private final List<String> calls = new ArrayList<>();
        private final CountDownLatch prereqStarted = new CountDownLatch(2);
        private final CountDownLatch analyzerStarted = new CountDownLatch(3);
        private boolean parseAndFactsWereConcurrentlyStarted;
        private boolean analyzersWereConcurrentlyStarted;
        private ReportActivityInput reportInput;

        private RecordingActivities(boolean requireConcurrentFanOut) {
            this.requireConcurrentFanOut = requireConcurrentFanOut;
        }

        @Override
        public synchronized String decompile(DecompileActivityInput input) {
            calls.add("decompile:" + input.sourcesDirKey());
            return input.sourcesDirKey();
        }

        @Override
        public String parseSources(ParseActivityInput input) {
            awaitFanOutIfRequired(prereqStarted);
            synchronized (this) {
                parseAndFactsWereConcurrentlyStarted = true;
                calls.add("parse:" + input.astIndexDirKey());
            }
            return input.astIndexDirKey();
        }

        @Override
        public String extractManifestFacts(ManifestFactsActivityInput input) {
            awaitFanOutIfRequired(prereqStarted);
            synchronized (this) {
                parseAndFactsWereConcurrentlyStarted = true;
                calls.add("manifest-facts:" + input.factsKey());
            }
            return input.factsKey();
        }

        @Override
        public String runTaint(TaintActivityInput input) {
            awaitFanOutIfRequired(analyzerStarted);
            synchronized (this) {
                analyzersWereConcurrentlyStarted = true;
                calls.add("taint:" + input.analysisName() + ":" + input.findingsKey());
            }
            return input.findingsKey();
        }

        @Override
        public String runManifestMisconfig(MisconfigActivityInput input) {
            awaitFanOutIfRequired(analyzerStarted);
            synchronized (this) {
                analyzersWereConcurrentlyStarted = true;
                calls.add("misconfig:" + input.analysisName() + ":" + input.findingsKey());
            }
            return input.findingsKey();
        }

        @Override
        public synchronized ReportArtifacts report(ReportActivityInput input) {
            this.reportInput = input;
            calls.add("report:" + input.htmlKey() + ":" + input.sarifKey());
            return new ReportArtifacts(input.htmlKey(), input.sarifKey());
        }

        private void awaitFanOutIfRequired(CountDownLatch latch) {
            if (!requireConcurrentFanOut) {
                return;
            }
            latch.countDown();
            try {
                if (!latch.await(5, TimeUnit.SECONDS)) {
                    throw new AssertionError("fan-out branch did not start concurrently");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new AssertionError("interrupted while waiting for fan-out", e);
            }
        }
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./gradlew :orchestrator:test --tests 'com.oversecured.sast.orchestrator.AnalyzeApkWorkflowTest'`

Expected: FAIL with compilation errors for missing `AnalyzeApkWorkflow` and `AnalyzeApkWorkflowImpl`.

- [ ] **Step 3: Write workflow interface**

Create `orchestrator/src/main/java/com/oversecured/sast/orchestrator/workflow/AnalyzeApkWorkflow.java`:

```java
package com.oversecured.sast.orchestrator.workflow;

import com.oversecured.sast.orchestrator.AnalysisResult;
import com.oversecured.sast.orchestrator.AnalyzeApkRequest;
import io.temporal.workflow.WorkflowInterface;
import io.temporal.workflow.WorkflowMethod;

@WorkflowInterface
public interface AnalyzeApkWorkflow {

    @WorkflowMethod
    AnalysisResult analyze(AnalyzeApkRequest request);
}
```

- [ ] **Step 4: Write workflow implementation**

Create `orchestrator/src/main/java/com/oversecured/sast/orchestrator/workflow/AnalyzeApkWorkflowImpl.java`:

```java
package com.oversecured.sast.orchestrator.workflow;

import com.oversecured.sast.orchestrator.AnalysisPlan;
import com.oversecured.sast.orchestrator.AnalysisResult;
import com.oversecured.sast.orchestrator.AnalyzeApkRequest;
import com.oversecured.sast.orchestrator.TaskQueues;
import com.oversecured.sast.orchestrator.activities.DecompileActivityInput;
import com.oversecured.sast.orchestrator.activities.ManifestFactsActivityInput;
import com.oversecured.sast.orchestrator.activities.MisconfigActivityInput;
import com.oversecured.sast.orchestrator.activities.ParseActivityInput;
import com.oversecured.sast.orchestrator.activities.PipelineActivities;
import com.oversecured.sast.orchestrator.activities.ReportActivityInput;
import com.oversecured.sast.orchestrator.activities.ReportArtifacts;
import com.oversecured.sast.orchestrator.activities.TaintActivityInput;
import io.temporal.activity.ActivityOptions;
import io.temporal.common.RetryOptions;
import io.temporal.workflow.Async;
import io.temporal.workflow.Promise;
import io.temporal.workflow.Workflow;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

public final class AnalyzeApkWorkflowImpl implements AnalyzeApkWorkflow {

    private final PipelineActivities activities = Workflow.newActivityStub(
            PipelineActivities.class,
            ActivityOptions.newBuilder()
                    .setTaskQueue(TaskQueues.DEFAULT)
                    .setStartToCloseTimeout(Duration.ofMinutes(30))
                    .setScheduleToCloseTimeout(Duration.ofHours(2))
                    .setRetryOptions(RetryOptions.newBuilder()
                            .setInitialInterval(Duration.ofSeconds(1))
                            .setBackoffCoefficient(2.0)
                            .setMaximumInterval(Duration.ofSeconds(30))
                            .setMaximumAttempts(3)
                            .build())
                    .build());

    @Override
    public AnalysisResult analyze(AnalyzeApkRequest request) {
        AnalysisPlan plan = request.plan();

        String sourcesDirKey = activities.decompile(new DecompileActivityInput(
                request.apkPath(),
                plan.keys().sourcesDirKey(),
                plan.keys().manifestKey()));

        Promise<String> astIndex = Async.function(activities::parseSources, new ParseActivityInput(
                sourcesDirKey,
                plan.keys().astIndexDirKey()));

        Promise<String> facts = Async.function(activities::extractManifestFacts, new ManifestFactsActivityInput(
                plan.keys().manifestKey(),
                plan.keys().factsKey()));

        Promise.allOf(astIndex, facts).get();

        List<Promise<String>> analyzerFindings = new ArrayList<>();
        for (AnalysisPlan.TaintAnalysis taint : plan.taintAnalyses()) {
            analyzerFindings.add(Async.function(activities::runTaint, new TaintActivityInput(
                    taint.name(),
                    astIndex.get(),
                    facts.get(),
                    taint.rulePath(),
                    taint.findingsKey())));
        }
        analyzerFindings.add(Async.function(activities::runManifestMisconfig, new MisconfigActivityInput(
                plan.manifestMisconfig().name(),
                facts.get(),
                plan.manifestMisconfig().rulePath(),
                plan.manifestMisconfig().findingsKey())));

        Promise.allOf(analyzerFindings).get();

        ReportArtifacts report = activities.report(new ReportActivityInput(
                plan.findingsKeysForReporter(),
                plan.report().htmlKey(),
                plan.report().sarifKey()));

        return new AnalysisResult(report.htmlKey(), report.sarifKey());
    }
}
```

- [ ] **Step 5: Run workflow tests**

Run: `./gradlew :orchestrator:test --tests 'com.oversecured.sast.orchestrator.AnalyzeApkWorkflowTest'`

Expected: PASS. Both tests pass. The second test would hang and fail if parse/manifest-facts or analyzer branches were scheduled sequentially.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/src/main/java/com/oversecured/sast/orchestrator/workflow orchestrator/src/test/java/com/oversecured/sast/orchestrator/AnalyzeApkWorkflowTest.java
git commit -m "feat(orchestrator): implement Temporal workflow DAG fan-out fan-in"
```

---

### Task 4: Activity implementation that calls step library APIs and preserves idempotent artifact wiring

**Files:**
- Create: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/activities/PipelineActivitiesImpl.java`
- Test: `orchestrator/src/test/java/com/oversecured/sast/orchestrator/PipelineActivitiesImplTest.java`

**Interfaces:**
- Consumes: activity records, `ActivityPathResolver`, step library APIs.
- Produces: activity implementation that resolves artifact keys to local paths, invokes step APIs, and returns the exact output key supplied by the workflow.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/src/test/java/com/oversecured/sast/orchestrator/PipelineActivitiesImplTest.java`:

```java
package com.oversecured.sast.orchestrator;

import static org.assertj.core.api.Assertions.assertThat;

import com.oversecured.sast.orchestrator.activities.DecompileActivityInput;
import com.oversecured.sast.orchestrator.activities.ManifestFactsActivityInput;
import com.oversecured.sast.orchestrator.activities.MisconfigActivityInput;
import com.oversecured.sast.orchestrator.activities.ParseActivityInput;
import com.oversecured.sast.orchestrator.activities.PipelineActivitiesImpl;
import com.oversecured.sast.orchestrator.activities.ReportActivityInput;
import com.oversecured.sast.orchestrator.activities.ReportArtifacts;
import com.oversecured.sast.orchestrator.activities.TaintActivityInput;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PipelineActivitiesImplTest {

    @Test
    void activitiesResolveKeysAndReturnRequestedOutputs(@TempDir Path root) throws Exception {
        RecordingStepApis apis = new RecordingStepApis();
        PipelineActivitiesImpl activities = PipelineActivitiesImpl.forTesting(root, apis);
        Files.writeString(root.resolve("apk.apk"), "fake-apk");

        String sourcesKey = activities.decompile(new DecompileActivityInput(
                root.resolve("apk.apk").toString(),
                "runs/r1/sources",
                "runs/r1/sources/AndroidManifest.xml"));
        String astKey = activities.parseSources(new ParseActivityInput(
                "runs/r1/sources",
                "runs/r1/ast-index"));
        String factsKey = activities.extractManifestFacts(new ManifestFactsActivityInput(
                "runs/r1/sources/AndroidManifest.xml",
                "runs/r1/facts.json"));
        String webviewKey = activities.runTaint(new TaintActivityInput(
                "webview",
                "runs/r1/ast-index",
                "runs/r1/facts.json",
                "rules/webview.yaml",
                "runs/r1/findings-webview.json"));
        String misconfigKey = activities.runManifestMisconfig(new MisconfigActivityInput(
                "manifest-misconfig",
                "runs/r1/facts.json",
                "rules/misconfig.yaml",
                "runs/r1/findings-misconfig.json"));
        ReportArtifacts reports = activities.report(new ReportActivityInput(
                List.of(webviewKey, misconfigKey),
                "runs/r1/report.html",
                "runs/r1/report.sarif"));

        assertThat(sourcesKey).isEqualTo("runs/r1/sources");
        assertThat(astKey).isEqualTo("runs/r1/ast-index");
        assertThat(factsKey).isEqualTo("runs/r1/facts.json");
        assertThat(webviewKey).isEqualTo("runs/r1/findings-webview.json");
        assertThat(misconfigKey).isEqualTo("runs/r1/findings-misconfig.json");
        assertThat(reports).isEqualTo(new ReportArtifacts("runs/r1/report.html", "runs/r1/report.sarif"));

        assertThat(apis.calls).containsExactly(
                "decompile:" + root.resolve("apk.apk").toAbsolutePath().normalize() + "->" + root.resolve("runs/r1/sources").toAbsolutePath().normalize(),
                "parse:" + root.resolve("runs/r1/sources").toAbsolutePath().normalize() + "->" + root.resolve("runs/r1/ast-index").toAbsolutePath().normalize(),
                "mfacts:" + root.resolve("runs/r1/sources/AndroidManifest.xml").toAbsolutePath().normalize() + "->" + root.resolve("runs/r1/facts.json").toAbsolutePath().normalize(),
                "taint:webview:" + root.resolve("rules/webview.yaml").toAbsolutePath().normalize() + "->" + root.resolve("runs/r1/findings-webview.json").toAbsolutePath().normalize(),
                "misconfig:manifest-misconfig:" + root.resolve("rules/misconfig.yaml").toAbsolutePath().normalize() + "->" + root.resolve("runs/r1/findings-misconfig.json").toAbsolutePath().normalize(),
                "report:2->" + root.resolve("runs/r1/report.html").toAbsolutePath().normalize() + ":" + root.resolve("runs/r1/report.sarif").toAbsolutePath().normalize());
    }

    private static final class RecordingStepApis implements PipelineActivitiesImpl.StepApis {
        private final List<String> calls = new ArrayList<>();

        @Override
        public void decompile(Path apk, Path sourcesDir) {
            calls.add("decompile:" + apk + "->" + sourcesDir);
        }

        @Override
        public void parse(Path sourcesDir, Path astIndexDir) {
            calls.add("parse:" + sourcesDir + "->" + astIndexDir);
        }

        @Override
        public void extractManifestFacts(Path manifestXml, Path factsJson) {
            calls.add("mfacts:" + manifestXml + "->" + factsJson);
        }

        @Override
        public void runTaint(String analysisName, Path astIndexDir, Path factsJson, Path ruleYaml, Path findingsJson) {
            calls.add("taint:" + analysisName + ":" + ruleYaml + "->" + findingsJson);
        }

        @Override
        public void runManifestMisconfig(String analysisName, Path factsJson, Path ruleYaml, Path findingsJson) {
            calls.add("misconfig:" + analysisName + ":" + ruleYaml + "->" + findingsJson);
        }

        @Override
        public void report(List<Path> findingsFiles, Path html, Path sarif) {
            calls.add("report:" + findingsFiles.size() + "->" + html + ":" + sarif);
        }
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./gradlew :orchestrator:test --tests 'com.oversecured.sast.orchestrator.PipelineActivitiesImplTest'`

Expected: FAIL with compilation error for missing `PipelineActivitiesImpl`.

- [ ] **Step 3: Write `PipelineActivitiesImpl.java`**

Create `orchestrator/src/main/java/com/oversecured/sast/orchestrator/activities/PipelineActivitiesImpl.java`:

```java
package com.oversecured.sast.orchestrator.activities;

import com.oversecured.sast.decompiler.Decompiler;
import com.oversecured.sast.parser.AstIndex;
import com.oversecured.sast.reporter.FindingsMerger;
import com.oversecured.sast.reporter.HtmlReportRenderer;
import com.oversecured.sast.reporter.SarifReportWriter;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public final class PipelineActivitiesImpl implements PipelineActivities {

    private final ActivityPathResolver paths;
    private final StepApis apis;

    public PipelineActivitiesImpl(Path artifactRoot) {
        this(artifactRoot, new ProductionStepApis());
    }

    private PipelineActivitiesImpl(Path artifactRoot, StepApis apis) {
        this.paths = new ActivityPathResolver(artifactRoot);
        this.apis = apis;
    }

    public static PipelineActivitiesImpl forTesting(Path artifactRoot, StepApis apis) {
        return new PipelineActivitiesImpl(artifactRoot, apis);
    }

    @Override
    public String decompile(DecompileActivityInput input) {
        Path apk = paths.resolveInputPath(input.apkPath());
        Path sourcesDir = paths.resolveArtifactKey(input.sourcesDirKey());
        apis.decompile(apk, sourcesDir);
        return input.sourcesDirKey();
    }

    @Override
    public String parseSources(ParseActivityInput input) {
        Path sourcesDir = paths.resolveArtifactKey(input.sourcesDirKey());
        Path astIndexDir = paths.resolveArtifactKey(input.astIndexDirKey());
        apis.parse(sourcesDir, astIndexDir);
        return input.astIndexDirKey();
    }

    @Override
    public String extractManifestFacts(ManifestFactsActivityInput input) {
        Path manifestXml = paths.resolveArtifactKey(input.manifestKey());
        Path factsJson = paths.resolveArtifactKey(input.factsKey());
        apis.extractManifestFacts(manifestXml, factsJson);
        return input.factsKey();
    }

    @Override
    public String runTaint(TaintActivityInput input) {
        Path astIndexDir = paths.resolveArtifactKey(input.astIndexDirKey());
        Path factsJson = paths.resolveArtifactKey(input.factsKey());
        Path ruleYaml = paths.resolveArtifactKey(input.rulePath());
        Path findingsJson = paths.resolveArtifactKey(input.findingsKey());
        apis.runTaint(input.analysisName(), astIndexDir, factsJson, ruleYaml, findingsJson);
        return input.findingsKey();
    }

    @Override
    public String runManifestMisconfig(MisconfigActivityInput input) {
        Path factsJson = paths.resolveArtifactKey(input.factsKey());
        Path ruleYaml = paths.resolveArtifactKey(input.rulePath());
        Path findingsJson = paths.resolveArtifactKey(input.findingsKey());
        apis.runManifestMisconfig(input.analysisName(), factsJson, ruleYaml, findingsJson);
        return input.findingsKey();
    }

    @Override
    public ReportArtifacts report(ReportActivityInput input) {
        List<Path> findingsFiles = input.findingsKeys().stream()
                .map(paths::resolveArtifactKey)
                .toList();
        Path html = paths.resolveArtifactKey(input.htmlKey());
        Path sarif = paths.resolveArtifactKey(input.sarifKey());
        apis.report(findingsFiles, html, sarif);
        return new ReportArtifacts(input.htmlKey(), input.sarifKey());
    }

    public interface StepApis {
        void decompile(Path apk, Path sourcesDir);

        void parse(Path sourcesDir, Path astIndexDir);

        void extractManifestFacts(Path manifestXml, Path factsJson);

        void runTaint(String analysisName, Path astIndexDir, Path factsJson, Path ruleYaml, Path findingsJson);

        void runManifestMisconfig(String analysisName, Path factsJson, Path ruleYaml, Path findingsJson);

        void report(List<Path> findingsFiles, Path html, Path sarif);
    }

    private static final class ProductionStepApis implements StepApis {
        @Override
        public void decompile(Path apk, Path sourcesDir) {
            new Decompiler().decompile(apk, sourcesDir);
        }

        @Override
        public void parse(Path sourcesDir, Path astIndexDir) {
            AstIndex.build(sourcesDir).save(astIndexDir);
        }

        @Override
        public void extractManifestFacts(Path manifestXml, Path factsJson) {
            new com.oversecured.sast.manifestfacts.ManifestFactsApp()
                    .extract(manifestXml, factsJson);
        }

        @Override
        public void runTaint(String analysisName, Path astIndexDir, Path factsJson, Path ruleYaml, Path findingsJson) {
            new com.oversecured.sast.taint.TaintAnalyzer()
                    .run(astIndexDir, factsJson, ruleYaml, findingsJson);
        }

        @Override
        public void runManifestMisconfig(String analysisName, Path factsJson, Path ruleYaml, Path findingsJson) {
            new com.oversecured.sast.misconfig.MisconfigApp()
                    .analyze(factsJson, ruleYaml, findingsJson);
        }

        @Override
        public void report(List<Path> findingsFiles, Path html, Path sarif) {
            try {
                Files.createDirectories(html.getParent());
                Files.createDirectories(sarif.getParent());
                var findings = new FindingsMerger().merge(findingsFiles);
                Files.writeString(html, new HtmlReportRenderer().render(findings));
                Files.writeString(sarif, new SarifReportWriter().toSarifJson(findings));
            } catch (IOException e) {
                throw new UncheckedIOException("failed to write reports", e);
            }
        }
    }
}
```

- [ ] **Step 4: Run activity implementation tests**

Run: `./gradlew :orchestrator:test --tests 'com.oversecured.sast.orchestrator.PipelineActivitiesImplTest'`

Expected: PASS. The test proves all activity outputs are returned from caller-supplied keys rather than generated internally.

- [ ] **Step 5: Run orchestrator tests together**

Run: `./gradlew :orchestrator:test --tests 'com.oversecured.sast.orchestrator.*'`

Expected: PASS for `AnalysisPlanTest`, `ActivityPathResolverTest`, `AnalyzeApkWorkflowTest`, and `PipelineActivitiesImplTest`.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/src/main/java/com/oversecured/sast/orchestrator/activities/PipelineActivitiesImpl.java orchestrator/src/test/java/com/oversecured/sast/orchestrator/PipelineActivitiesImplTest.java
git commit -m "feat(orchestrator): wire activities to step library APIs"
```

---

### Task 5: Worker main and workflow starter CLI

**Files:**
- Create: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/cli/WorkerMain.java`
- Create: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/cli/StartAnalysisCommand.java`
- Test: `orchestrator/src/test/java/com/oversecured/sast/orchestrator/StartAnalysisCommandTest.java`

**Interfaces:**
- Consumes: workflow interface, workflow implementation, `PipelineActivitiesImpl`, `AnalysisPlan`.
- Produces:
  - Worker process that registers workflow/activity implementations on `android-sast-pipeline`.
  - CLI starter: `start-analysis --apk <path> --run-id <id> --temporal <host:port>`.

- [ ] **Step 1: Write the failing CLI tests**

Create `orchestrator/src/test/java/com/oversecured/sast/orchestrator/StartAnalysisCommandTest.java`:

```java
package com.oversecured.sast.orchestrator;

import static org.assertj.core.api.Assertions.assertThat;

import com.oversecured.sast.orchestrator.cli.StartAnalysisCommand;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

class StartAnalysisCommandTest {

    @Test
    void commandBuildsRequestAndStartsWorkflow() {
        RecordingStarter starter = new RecordingStarter();
        int exit = new CommandLine(new StartAnalysisCommand(starter)).execute(
                "--apk", "/tmp/ovaa.apk",
                "--run-id", "ovaa-001",
                "--temporal", "127.0.0.1:7233");

        assertThat(exit).isEqualTo(0);
        assertThat(starter.target).isEqualTo("127.0.0.1:7233");
        assertThat(starter.workflowId).isEqualTo("android-sast-ovaa-001");
        assertThat(starter.requests).containsExactly(new AnalyzeApkRequest(
                "/tmp/ovaa.apk",
                AnalysisPlan.defaultPlan("ovaa-001")));
    }

    @Test
    void commandRejectsUnsafeRunIdBeforeStartingWorkflow() {
        RecordingStarter starter = new RecordingStarter();
        int exit = new CommandLine(new StartAnalysisCommand(starter)).execute(
                "--apk", "/tmp/ovaa.apk",
                "--run-id", "../escape");

        assertThat(exit).isNotEqualTo(0);
        assertThat(starter.requests).isEmpty();
    }

    private static final class RecordingStarter implements StartAnalysisCommand.WorkflowStarter {
        private String target;
        private String workflowId;
        private final List<AnalyzeApkRequest> requests = new ArrayList<>();

        @Override
        public AnalysisResult start(String temporalTarget, String workflowId, AnalyzeApkRequest request) {
            this.target = temporalTarget;
            this.workflowId = workflowId;
            this.requests.add(request);
            return new AnalysisResult(request.plan().report().htmlKey(), request.plan().report().sarifKey());
        }
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./gradlew :orchestrator:test --tests 'com.oversecured.sast.orchestrator.StartAnalysisCommandTest'`

Expected: FAIL with compilation error for missing `StartAnalysisCommand`.

- [ ] **Step 3: Write `StartAnalysisCommand.java`**

Create `orchestrator/src/main/java/com/oversecured/sast/orchestrator/cli/StartAnalysisCommand.java`:

```java
package com.oversecured.sast.orchestrator.cli;

import com.oversecured.sast.orchestrator.AnalysisPlan;
import com.oversecured.sast.orchestrator.AnalysisResult;
import com.oversecured.sast.orchestrator.AnalyzeApkRequest;
import com.oversecured.sast.orchestrator.TaskQueues;
import com.oversecured.sast.orchestrator.workflow.AnalyzeApkWorkflow;
import io.temporal.client.WorkflowClient;
import io.temporal.client.WorkflowOptions;
import io.temporal.serviceclient.WorkflowServiceStubs;
import io.temporal.serviceclient.WorkflowServiceStubsOptions;
import java.util.concurrent.Callable;
import picocli.CommandLine;

@CommandLine.Command(name = "start-analysis", mixinStandardHelpOptions = true)
public final class StartAnalysisCommand implements Callable<Integer> {

    @CommandLine.Option(names = "--apk", required = true)
    private String apk;

    @CommandLine.Option(names = "--run-id", required = true)
    private String runId;

    @CommandLine.Option(names = "--temporal", defaultValue = "127.0.0.1:7233")
    private String temporalTarget;

    private final WorkflowStarter starter;

    public StartAnalysisCommand() {
        this(new TemporalWorkflowStarter());
    }

    public StartAnalysisCommand(WorkflowStarter starter) {
        this.starter = starter;
    }

    @Override
    public Integer call() {
        AnalysisPlan plan = AnalysisPlan.defaultPlan(runId);
        String workflowId = "android-sast-" + runId;
        AnalysisResult result = starter.start(temporalTarget, workflowId, new AnalyzeApkRequest(apk, plan));
        System.out.println("html=" + result.htmlReportKey());
        System.out.println("sarif=" + result.sarifReportKey());
        return 0;
    }

    public static void main(String[] args) {
        System.exit(new CommandLine(new StartAnalysisCommand()).execute(args));
    }

    public interface WorkflowStarter {
        AnalysisResult start(String temporalTarget, String workflowId, AnalyzeApkRequest request);
    }

    private static final class TemporalWorkflowStarter implements WorkflowStarter {
        @Override
        public AnalysisResult start(String temporalTarget, String workflowId, AnalyzeApkRequest request) {
            WorkflowServiceStubs service = WorkflowServiceStubs.newServiceStubs(
                    WorkflowServiceStubsOptions.newBuilder()
                            .setTarget(temporalTarget)
                            .build());
            WorkflowClient client = WorkflowClient.newInstance(service);
            AnalyzeApkWorkflow workflow = client.newWorkflowStub(
                    AnalyzeApkWorkflow.class,
                    WorkflowOptions.newBuilder()
                            .setWorkflowId(workflowId)
                            .setTaskQueue(TaskQueues.DEFAULT)
                            .build());
            return workflow.analyze(request);
        }
    }
}
```

- [ ] **Step 4: Write `WorkerMain.java`**

Create `orchestrator/src/main/java/com/oversecured/sast/orchestrator/cli/WorkerMain.java`:

```java
package com.oversecured.sast.orchestrator.cli;

import com.oversecured.sast.orchestrator.TaskQueues;
import com.oversecured.sast.orchestrator.activities.PipelineActivitiesImpl;
import com.oversecured.sast.orchestrator.workflow.AnalyzeApkWorkflowImpl;
import io.temporal.client.WorkflowClient;
import io.temporal.serviceclient.WorkflowServiceStubs;
import io.temporal.serviceclient.WorkflowServiceStubsOptions;
import io.temporal.worker.Worker;
import io.temporal.worker.WorkerFactory;
import java.nio.file.Path;

public final class WorkerMain {

    private WorkerMain() {
    }

    public static void main(String[] args) {
        String temporalTarget = env("TEMPORAL_ADDRESS", "127.0.0.1:7233");
        Path artifactRoot = Path.of(env("ARTIFACT_ROOT", "artifacts"));

        WorkflowServiceStubs service = WorkflowServiceStubs.newServiceStubs(
                WorkflowServiceStubsOptions.newBuilder()
                        .setTarget(temporalTarget)
                        .build());
        WorkflowClient client = WorkflowClient.newInstance(service);
        WorkerFactory factory = WorkerFactory.newInstance(client);
        Worker worker = factory.newWorker(TaskQueues.DEFAULT);

        worker.registerWorkflowImplementationTypes(AnalyzeApkWorkflowImpl.class);
        worker.registerActivitiesImplementations(new PipelineActivitiesImpl(artifactRoot));
        factory.start();

        Runtime.getRuntime().addShutdownHook(new Thread(factory::shutdown));
        System.out.println("orchestrator worker started on taskQueue=" + TaskQueues.DEFAULT);
    }

    private static String env(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? fallback : value;
    }
}
```

- [ ] **Step 5: Run CLI tests**

Run: `./gradlew :orchestrator:test --tests 'com.oversecured.sast.orchestrator.StartAnalysisCommandTest'`

Expected: PASS. Both CLI tests pass.

- [ ] **Step 6: Run install distribution**

Run: `./gradlew :orchestrator:installDist`

Expected: PASS. `orchestrator/build/install/orchestrator/bin/orchestrator` is generated with `WorkerMain` as the application entrypoint.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/src/main/java/com/oversecured/sast/orchestrator/cli orchestrator/src/test/java/com/oversecured/sast/orchestrator/StartAnalysisCommandTest.java
git commit -m "feat(orchestrator): add worker main and workflow starter CLI"
```

---

### Task 6: Docker Compose runtime for Temporal, UI, Postgres, worker, and artifacts

**Files:**
- Create: `docker-compose.yml`
- Create: `orchestrator/Dockerfile`

**Interfaces:**
- Consumes: `WorkerMain`, Gradle install distribution.
- Produces:
  - `temporal` server on `127.0.0.1:7233`
  - `temporal-ui` on `127.0.0.1:8080`
  - `postgres` persistence
  - `worker` running `WorkerMain`
  - local artifact volume mounted at `/workspace/artifacts`
  - optional MinIO profile for future S3-compatible storage experiments without changing workflow keys

- [ ] **Step 1: Write `orchestrator/Dockerfile`**

```dockerfile
FROM eclipse-temurin:17-jdk AS build
WORKDIR /workspace
COPY . .
RUN ./gradlew :orchestrator:installDist --no-daemon

FROM eclipse-temurin:17-jre
WORKDIR /workspace
COPY --from=build /workspace/orchestrator/build/install/orchestrator /opt/orchestrator
ENV TEMPORAL_ADDRESS=temporal:7233
ENV ARTIFACT_ROOT=/workspace/artifacts
ENTRYPOINT ["/opt/orchestrator/bin/orchestrator"]
```

- [ ] **Step 2: Write `docker-compose.yml`**

```yaml
services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_USER: temporal
      POSTGRES_PASSWORD: temporal
    ports:
      - "5432:5432"
    volumes:
      - temporal-postgres:/var/lib/postgresql/data

  temporal:
    image: temporalio/auto-setup:1.29.6
    depends_on:
      - postgres
    environment:
      DB: postgresql
      DB_PORT: "5432"
      POSTGRES_USER: temporal
      POSTGRES_PWD: temporal
      POSTGRES_SEEDS: postgres
      DYNAMIC_CONFIG_FILE_PATH: config/dynamicconfig/development-sql.yaml
    ports:
      - "7233:7233"

  temporal-ui:
    image: temporalio/ui:2.51.0
    depends_on:
      - temporal
    environment:
      TEMPORAL_ADDRESS: temporal:7233
      TEMPORAL_CORS_ORIGINS: http://localhost:3000
    ports:
      - "8080:8080"

  worker:
    build:
      context: .
      dockerfile: orchestrator/Dockerfile
    depends_on:
      - temporal
    environment:
      TEMPORAL_ADDRESS: temporal:7233
      ARTIFACT_ROOT: /workspace/artifacts
    volumes:
      - ./artifacts:/workspace/artifacts
      - ./rules:/workspace/artifacts/rules:ro
      - ./test-subjects:/workspace/test-subjects:ro

  minio:
    image: minio/minio:RELEASE.2026-05-24T17-08-30Z
    profiles:
      - minio
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: minioadmin
      MINIO_ROOT_PASSWORD: minioadmin
    ports:
      - "9000:9000"
      - "9001:9001"
    volumes:
      - minio-data:/data

volumes:
  temporal-postgres:
  minio-data:
```

- [ ] **Step 3: Validate compose syntax**

Run: `docker compose config`

Expected: PASS. The command prints a normalized compose file containing services `postgres`, `temporal`, `temporal-ui`, `worker`, and profiled service `minio`.

- [ ] **Step 4: Build the worker image**

Run: `docker compose build worker`

Expected: PASS. The build stage runs `./gradlew :orchestrator:installDist --no-daemon` and produces the worker image.

- [ ] **Step 5: Start Temporal stack**

Run: `docker compose up -d postgres temporal temporal-ui worker`

Expected: PASS. `docker compose ps` shows `postgres`, `temporal`, `temporal-ui`, and `worker` running. Temporal UI is reachable at `http://localhost:8080`.

- [ ] **Step 6: Start optional MinIO profile**

Run: `docker compose --profile minio up -d minio`

Expected: PASS. MinIO console is reachable at `http://localhost:9001`. The orchestrator still uses local volume artifacts in this plan; MinIO is present only as an optional local service for later `ArtifactStore` implementations.

- [ ] **Step 7: Commit**

```bash
git add docker-compose.yml orchestrator/Dockerfile
git commit -m "chore(orchestrator): add local Temporal docker compose runtime"
```

---

### Task 7: Retry and idempotency verification

**Files:**
- Modify: `orchestrator/src/test/java/com/oversecured/sast/orchestrator/AnalyzeApkWorkflowTest.java`

**Interfaces:**
- Consumes: workflow retry options and deterministic output keys.
- Produces: tests proving transient activity failures retry without changing artifact keys and permanent failures surface without running downstream steps.

- [ ] **Step 1: Add retry/idempotency tests**

Append these tests and nested activity class to `AnalyzeApkWorkflowTest.java`:

```java
    @Test
    void transientAnalyzerFailureRetriesWithSameOutputKey() {
        RetryRecordingActivities activities = new RetryRecordingActivities(2);
        AnalyzeApkWorkflow workflow = newWorkflow(activities);

        AnalysisResult result = workflow.analyze(
                new AnalyzeApkRequest("/tmp/ovaa.apk", AnalysisPlan.defaultPlan("retry-1")));

        assertThat(result.sarifReportKey()).isEqualTo("runs/retry-1/report.sarif");
        assertThat(activities.webviewAttempts).isEqualTo(2);
        assertThat(activities.webviewKeys).containsExactly(
                "runs/retry-1/findings-webview.json",
                "runs/retry-1/findings-webview.json");
        assertThat(activities.reportCalled).isTrue();
    }

    @Test
    void permanentDecompilerFailureStopsDownstreamActivities() {
        RetryRecordingActivities activities = new RetryRecordingActivities(Integer.MAX_VALUE);
        activities.failDecompile = true;
        AnalyzeApkWorkflow workflow = newWorkflow(activities);

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> workflow.analyze(
                        new AnalyzeApkRequest("/tmp/missing.apk", AnalysisPlan.defaultPlan("fail-1"))))
                .hasMessageContaining("decompile failed");

        assertThat(activities.parseCalled).isFalse();
        assertThat(activities.reportCalled).isFalse();
    }

    private static final class RetryRecordingActivities implements PipelineActivities {
        private final int webviewSucceedsOnAttempt;
        private int webviewAttempts;
        private final List<String> webviewKeys = new ArrayList<>();
        private boolean failDecompile;
        private boolean parseCalled;
        private boolean reportCalled;

        private RetryRecordingActivities(int webviewSucceedsOnAttempt) {
            this.webviewSucceedsOnAttempt = webviewSucceedsOnAttempt;
        }

        @Override
        public String decompile(DecompileActivityInput input) {
            if (failDecompile) {
                throw new IllegalStateException("decompile failed");
            }
            return input.sourcesDirKey();
        }

        @Override
        public String parseSources(ParseActivityInput input) {
            parseCalled = true;
            return input.astIndexDirKey();
        }

        @Override
        public String extractManifestFacts(ManifestFactsActivityInput input) {
            return input.factsKey();
        }

        @Override
        public String runTaint(TaintActivityInput input) {
            if ("webview".equals(input.analysisName())) {
                webviewAttempts++;
                webviewKeys.add(input.findingsKey());
                if (webviewAttempts < webviewSucceedsOnAttempt) {
                    throw new IllegalStateException("temporary taint failure");
                }
            }
            return input.findingsKey();
        }

        @Override
        public String runManifestMisconfig(MisconfigActivityInput input) {
            return input.findingsKey();
        }

        @Override
        public ReportArtifacts report(ReportActivityInput input) {
            reportCalled = true;
            return new ReportArtifacts(input.htmlKey(), input.sarifKey());
        }
    }
```

- [ ] **Step 2: Run retry tests**

Run: `./gradlew :orchestrator:test --tests 'com.oversecured.sast.orchestrator.AnalyzeApkWorkflowTest'`

Expected: PASS. The retry test records two attempts for `runs/retry-1/findings-webview.json`; the permanent failure test records no parse/report calls.

- [ ] **Step 3: Commit**

```bash
git add orchestrator/src/test/java/com/oversecured/sast/orchestrator/AnalyzeApkWorkflowTest.java
git commit -m "test(orchestrator): verify activity retry idempotency and failure short-circuit"
```

---

### Task 8: End-to-end local smoke command and final verification

**Files:**
- Modify: `orchestrator/src/test/java/com/oversecured/sast/orchestrator/AnalyzeApkWorkflowTest.java` if Task 7 imports need cleanup.
- No new production files.

**Interfaces:**
- Consumes: all orchestrator production code and compose runtime.
- Produces: documented command sequence that starts the worker and submits an analysis using stable plan keys.

- [ ] **Step 1: Run all orchestrator tests**

Run: `./gradlew :orchestrator:test`

Expected: PASS. All orchestrator tests are green:

- `AnalysisPlanTest`
- `ActivityPathResolverTest`
- `AnalyzeApkWorkflowTest`
- `PipelineActivitiesImplTest`
- `StartAnalysisCommandTest`

- [ ] **Step 2: Run module build**

Run: `./gradlew :orchestrator:build`

Expected: PASS. The module compiles main/test code and builds the application distribution.

- [ ] **Step 3: Run full build graph after dependent modules are implemented**

Run: `./gradlew build`

Expected: PASS once `:apps:manifest-facts`, `:apps:taint`, and `:apps:manifest-misconfig` provide the library API classes named in the global constraints. If this fails before those modules exist, the failure should be a missing class in one of those modules, not an orchestrator test failure.

- [ ] **Step 4: Start local Temporal stack**

Run: `docker compose up -d postgres temporal temporal-ui worker`

Expected: PASS. `docker compose ps` shows the worker running and Temporal UI is available at `http://localhost:8080`.

- [ ] **Step 5: Submit one local workflow**

Run:

```bash
./gradlew :orchestrator:run \
  --args='start-analysis --apk /workspace/test-subjects/apk/ovaa.apk --run-id ovaa-local --temporal 127.0.0.1:7233'
```

Expected: PASS when the sample APK path exists inside the same filesystem namespace as the worker. The command prints:

```text
html=runs/ovaa-local/report.html
sarif=runs/ovaa-local/report.sarif
```

For host-only execution without Docker, set `ARTIFACT_ROOT=artifacts` and use a host path for `--apk`.

- [ ] **Step 6: Verify report artifacts**

Run:

```bash
test -f artifacts/runs/ovaa-local/report.html
test -f artifacts/runs/ovaa-local/report.sarif
```

Expected: PASS. Both files exist after the workflow completes.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/src/test/java/com/oversecured/sast/orchestrator/AnalyzeApkWorkflowTest.java
git commit -m "test(orchestrator): add final workflow verification coverage"
```

---

## Self-Review

**Spec coverage:**
- `:orchestrator` module and `com.oversecured.sast.orchestrator` package root are used throughout.
- Temporal workflow shape matches the required DAG: decompile, parallel parse/manifest-facts, parallel taint webview/taint pathtraversal/manifest-misconfig, reporter fan-in.
- Orchestrator contains no analysis logic; `PipelineActivitiesImpl` delegates to step library APIs and handles only path/key wiring.
- `AnalysisPlan` owns rule files and output artifact keys.
- Docker Compose includes Temporal, Temporal UI, Postgres, worker, local artifact volume, and optional MinIO.
- Tests cover DAG order, fan-out/fan-in, artifact key wiring, retry/idempotency assumptions, and CLI/workflow starter behavior.

**Placeholder scan:** The plan contains concrete class names, method signatures, commands, expected results, and commit messages. No empty implementation markers are used.

**Type consistency:**
- `AnalysisPlan.defaultPlan(runId)` generates the exact keys consumed by `AnalyzeApkWorkflowImpl` and asserted in tests.
- `PipelineActivities` method names match workflow calls and activity implementation methods.
- `ReportActivityInput.findingsKeys()` order matches `AnalysisPlan.findingsKeysForReporter()`.
- `AnalysisResult` uses the same report keys returned by `ReportArtifacts`.
- `TaskQueues.DEFAULT` is used consistently by workflow tests, worker registration, and starter workflow options.
