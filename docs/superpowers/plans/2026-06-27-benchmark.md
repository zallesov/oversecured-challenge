# Benchmark / E2E Harness Implementation Plan

**Shared conventions:** [Shared Contracts and Naming Conventions](../reference/2026-06-27-shared-contracts-and-conventions.md)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `:benchmark`, a black-box validation harness that runs OVAA end to end, scores selected DroidBench cases, and writes deterministic JSON/Markdown summaries without implementing analysis logic.

**Architecture:** The module treats the SAST pipeline as an external producer of artifacts: it invokes existing Gradle/CLI entrypoints, then reads `findings*.json` files into common `FindingsDoc`/`Finding` records using `common.Json`. Pure scoring classes compute TP/FP/FN, precision, recall, and F1 from expected leak specs versus reported findings; thin CLI/Gradle tasks handle process execution, filesystem layout, and output files. The harness never depends on `apps:taint`, `apps:manifest-misconfig`, parser internals, or reporter internals.

**Tech Stack:** Java 17; Gradle Groovy DSL; JUnit 5 + AssertJ; Jackson via `common.Json`; picocli for a small CLI; existing test subjects under `test-subjects/`.

## Global Constraints

- Module name: `:benchmark`.
- Package root: `com.oversecured.sast.benchmark`.
- `benchmark` is a library module, not an analyzer and not an application plugin module. It may expose `JavaExec` Gradle tasks that run a `BenchmarkCli` main class.
- The harness must not implement taint propagation, manifest parsing, decompilation, AST parsing, reporter rendering, or rule interpretation.
- The only shared model dependency for findings is `common`: `FindingsDoc`, `Finding`, `FlowStep`, `Severity`, and `Json`.
- Inter-step communication is artifact-first. The harness reads `reports/findings` artifacts from a run directory and never parses analyzer stdout.
- Fixture layout is consistent with the existing repository:
  - OVAA source: `test-subjects/source/ovaa/`
  - OVAA debug APK output: `test-subjects/source/ovaa/app/build/outputs/apk/debug/app-debug.apk`
  - DroidBench APKs: `test-subjects/apk/droidbench/<category>/<case>.apk`
  - DroidBench source and ground truth comments: `test-subjects/source/droidbench/<category>/<case>/`
  - Benchmark run output: `benchmark/build/reports/benchmark/<suite>/`
- OVAA validation builds the APK with `./gradlew assembleDebug` from `test-subjects/source/ovaa/` before running the pipeline.
- OVAA success criteria:
  - exactly 2 taint findings total;
  - required taint rule IDs are `ANDROID_WEBVIEW_INTENT_LOADURL` and `ANDROID_PATH_TRAVERSAL_PROVIDER`;
  - allowed manifest finding rule IDs are `exported_without_permission`, `exported_provider`, `provider_grant_uri_permissions`, and `weak_host_validation`;
  - 0 false positives against the OVAA target set.
- DroidBench scoring reports TP/FP/FN, precision, recall, F1, and per-case status. Out-of-scope categories are represented in the catalog as skipped with a reason, not silently ignored.
- JSON and Markdown summaries are written for every CLI run:
  - `benchmark/build/reports/benchmark/ovaa/summary.json`
  - `benchmark/build/reports/benchmark/ovaa/summary.md`
  - `benchmark/build/reports/benchmark/droidbench/summary.json`
  - `benchmark/build/reports/benchmark/droidbench/summary.md`
- Commands in this plan assume the common foundation has already created root `settings.gradle`, root `build.gradle`, and Gradle wrapper files.

## File Structure

```
challenge/
├── benchmark/
│   ├── build.gradle
│   └── src/
│       ├── main/java/com/oversecured/sast/benchmark/
│       │   ├── BenchmarkCli.java              # picocli CLI: ovaa, droidbench, score-artifacts
│       │   ├── BenchmarkPaths.java            # repo-relative path resolver
│       │   ├── BenchmarkReportWriter.java     # writes summary.json and summary.md
│       │   ├── CommandRunner.java             # process execution wrapper
│       │   ├── PipelineInvoker.java           # interface for black-box pipeline runs
│       │   ├── GradlePipelineInvoker.java     # invokes orchestrator/step Gradle tasks; no analysis logic
│       │   ├── FindingsArtifactReader.java    # reads findings*.json -> List<Finding>
│       │   ├── FindingFingerprint.java        # normalized ruleId + sink file/line identity
│       │   ├── ExpectedLeak.java              # expected benchmark leak identity
│       │   ├── BenchmarkCase.java             # suite/category/name/apk/source expected leaks
│       │   ├── CaseScore.java                 # per-case TP/FP/FN/result records
│       │   ├── ScoreSummary.java              # aggregate metrics and generated artifact paths
│       │   ├── FindingMatcher.java            # expected leak vs finding matching
│       │   ├── ScoreCalculator.java           # pure TP/FP/FN math
│       │   ├── OvaaExpectation.java           # OVAA required/allowed rule assertions
│       │   ├── OvaaBenchmark.java             # build OVAA, invoke pipeline, score artifacts
│       │   ├── DroidBenchGroundTruthParser.java # parses @number_of_leaks and source/sink comments
│       │   ├── DroidBenchCatalog.java         # discovers selected DroidBench cases
│       │   └── DroidBenchBenchmark.java       # runs selected cases and aggregates scores
│       └── test/
│           ├── java/com/oversecured/sast/benchmark/
│           │   ├── FindingsArtifactReaderTest.java
│           │   ├── ScoreCalculatorTest.java
│           │   ├── OvaaExpectationTest.java
│           │   ├── DroidBenchGroundTruthParserTest.java
│           │   ├── BenchmarkReportWriterTest.java
│           │   ├── BenchmarkCliTest.java
│           │   └── DroidBenchBenchmarkTest.java
│           └── resources/fixtures/
│               ├── findings/
│               │   ├── findings-webview.json
│               │   ├── findings-pathtraversal.json
│               │   └── findings-misconfig.json
│               └── droidbench/
│                   └── MiniLeak.java
└── test-subjects/
    ├── apk/droidbench/
    └── source/
        ├── droidbench/
        └── ovaa/
```

## Task 1: Gradle scaffolding and immutable score records

**Files:**
- Modify: `benchmark/build.gradle`
- Create: `benchmark/src/main/java/com/oversecured/sast/benchmark/ExpectedLeak.java`
- Create: `benchmark/src/main/java/com/oversecured/sast/benchmark/FindingFingerprint.java`
- Create: `benchmark/src/main/java/com/oversecured/sast/benchmark/BenchmarkCase.java`
- Create: `benchmark/src/main/java/com/oversecured/sast/benchmark/CaseScore.java`
- Create: `benchmark/src/main/java/com/oversecured/sast/benchmark/ScoreSummary.java`
- Test: `benchmark/src/test/java/com/oversecured/sast/benchmark/ScoreCalculatorTest.java`

**Interfaces:**
- Consumes: root Gradle `ext` versions from the common foundation plan.
- Produces: serializable scoring records used by every later task.

- [ ] **Step 1: Write the failing test**

`benchmark/src/test/java/com/oversecured/sast/benchmark/ScoreCalculatorTest.java`:

```java
package com.oversecured.sast.benchmark;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class ScoreCalculatorTest {

  @Test
  void scoreRecordsExposeStableMetrics() {
    ExpectedLeak expected = new ExpectedLeak(
        "ANDROID_WEBVIEW_INTENT_LOADURL", "WebViewActivity.java", 20, "loadUrl");
    FindingFingerprint actual = new FindingFingerprint(
        "ANDROID_WEBVIEW_INTENT_LOADURL", "WebViewActivity.java", 20, "sink: WebView.loadUrl(url)");
    BenchmarkCase c = new BenchmarkCase(
        "droidbench", "GeneralJava", "MiniLeak", Path.of("MiniLeak.apk"),
        Path.of("MiniLeak"), List.of(expected), false, "");
    CaseScore score = new CaseScore(c, 1, 0, 0, List.of(actual), List.of(), List.of());

    assertThat(score.precision()).isEqualTo(1.0d);
    assertThat(score.recall()).isEqualTo(1.0d);
    assertThat(score.f1()).isEqualTo(1.0d);
  }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :benchmark:test --tests 'com.oversecured.sast.benchmark.ScoreCalculatorTest'`

Expected: FAIL with compilation errors for missing `ExpectedLeak`, `FindingFingerprint`, `BenchmarkCase`, and `CaseScore`.

- [ ] **Step 3: Write minimal implementation**

`benchmark/build.gradle`:

```groovy
plugins {
    id 'java-library'
}

dependencies {
    api project(':common')
    implementation "info.picocli:picocli:${rootProject.ext.picocliVersion}"
    annotationProcessor "info.picocli:picocli-codegen:${rootProject.ext.picocliVersion}"
}
```

`ExpectedLeak.java`:

```java
package com.oversecured.sast.benchmark;

public record ExpectedLeak(String ruleId, String sinkFile, int sinkLine, String sinkLabelContains) {}
```

`FindingFingerprint.java`:

```java
package com.oversecured.sast.benchmark;

public record FindingFingerprint(String ruleId, String sinkFile, int sinkLine, String sinkLabel) {}
```

`BenchmarkCase.java`:

```java
package com.oversecured.sast.benchmark;

import java.nio.file.Path;
import java.util.List;

public record BenchmarkCase(
    String suite,
    String category,
    String name,
    Path apk,
    Path sourceDir,
    List<ExpectedLeak> expectedLeaks,
    boolean skipped,
    String skipReason) {}
```

`CaseScore.java`:

```java
package com.oversecured.sast.benchmark;

import java.util.List;

public record CaseScore(
    BenchmarkCase benchmarkCase,
    int truePositives,
    int falsePositives,
    int falseNegatives,
    List<FindingFingerprint> matchedFindings,
    List<FindingFingerprint> unexpectedFindings,
    List<ExpectedLeak> missedLeaks) {

  public double precision() {
    int denominator = truePositives + falsePositives;
    return denominator == 0 ? 1.0d : ((double) truePositives) / denominator;
  }

  public double recall() {
    int denominator = truePositives + falseNegatives;
    return denominator == 0 ? 1.0d : ((double) truePositives) / denominator;
  }

  public double f1() {
    double p = precision();
    double r = recall();
    return p + r == 0.0d ? 0.0d : (2.0d * p * r) / (p + r);
  }
}
```

`ScoreSummary.java`:

```java
package com.oversecured.sast.benchmark;

import java.nio.file.Path;
import java.util.List;

public record ScoreSummary(
    String suite,
    int casesRun,
    int casesSkipped,
    int truePositives,
    int falsePositives,
    int falseNegatives,
    double precision,
    double recall,
    double f1,
    List<CaseScore> cases,
    Path jsonSummary,
    Path markdownSummary) {}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :benchmark:test --tests 'com.oversecured.sast.benchmark.ScoreCalculatorTest'`

Expected: PASS (1 test).

- [ ] **Step 5: Commit**

```bash
git add benchmark/build.gradle benchmark/src/main/java/com/oversecured/sast/benchmark benchmark/src/test/java/com/oversecured/sast/benchmark/ScoreCalculatorTest.java
git commit -m "feat(benchmark): add score model records"
```

## Task 2: Read findings artifacts through common `Json`

**Files:**
- Create: `benchmark/src/main/java/com/oversecured/sast/benchmark/FindingsArtifactReader.java`
- Create: `benchmark/src/test/resources/fixtures/findings/findings-webview.json`
- Create: `benchmark/src/test/resources/fixtures/findings/findings-pathtraversal.json`
- Create: `benchmark/src/test/resources/fixtures/findings/findings-misconfig.json`
- Test: `benchmark/src/test/java/com/oversecured/sast/benchmark/FindingsArtifactReaderTest.java`

**Interfaces:**
- Consumes: `com.oversecured.sast.common.Json`, `FindingsDoc`, `Finding`, `FlowStep`, `Severity`.
- Produces: `FindingsArtifactReader.readFindings(Path reportsOrFindingsDir)` returning all findings from files named `findings*.json`.

- [ ] **Step 1: Write fixture JSON files**

`findings-webview.json`:

```json
{
  "analyzer": "taint-engine",
  "findings": [
    {
      "ruleId": "ANDROID_WEBVIEW_INTENT_LOADURL",
      "vulnerabilityClass": "webview-open-redirect",
      "severity": "ERROR",
      "message": "Untrusted deeplink data flows into WebView.loadUrl",
      "cwe": "CWE-601",
      "owaspMobile": "M1",
      "flow": [
        {"file": "DeeplinkActivity.java", "line": 47, "label": "source"},
        {"file": "WebViewActivity.java", "line": 20, "label": "sink: WebView.loadUrl(url)"}
      ],
      "notes": ["entry component exported via deeplink"]
    }
  ]
}
```

`findings-pathtraversal.json`:

```json
{
  "analyzer": "taint-engine",
  "findings": [
    {
      "ruleId": "ANDROID_PATH_TRAVERSAL_PROVIDER",
      "vulnerabilityClass": "path-traversal",
      "severity": "ERROR",
      "message": "Untrusted Uri path segment flows into file open",
      "cwe": "CWE-22",
      "owaspMobile": "M8",
      "flow": [
        {"file": "TheftOverwriteProvider.java", "line": 48, "label": "source: getLastPathSegment"},
        {"file": "TheftOverwriteProvider.java", "line": 49, "label": "sink: ParcelFileDescriptor.open(file)"}
      ],
      "notes": []
    }
  ]
}
```

`findings-misconfig.json`:

```json
{
  "analyzer": "manifest-misconfig",
  "findings": [
    {
      "ruleId": "exported_without_permission",
      "vulnerabilityClass": "manifest-misconfiguration",
      "severity": "WARNING",
      "message": "Exported component has no permission",
      "cwe": "CWE-926",
      "owaspMobile": "M1",
      "flow": [
        {"file": "AndroidManifest.xml", "line": 8, "label": "exported activity"}
      ],
      "notes": []
    }
  ]
}
```

- [ ] **Step 2: Write the failing test**

`FindingsArtifactReaderTest.java`:

```java
package com.oversecured.sast.benchmark;

import static org.assertj.core.api.Assertions.assertThat;

import com.oversecured.sast.common.Finding;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class FindingsArtifactReaderTest {

  @Test
  void readsEveryFindingsJsonArtifactInSortedOrder() throws Exception {
    Path dir = Path.of("src/test/resources/fixtures/findings").toAbsolutePath();
    List<Finding> findings = new FindingsArtifactReader().readFindings(dir);

    assertThat(findings).extracting(Finding::ruleId).containsExactly(
        "exported_without_permission",
        "ANDROID_PATH_TRAVERSAL_PROVIDER",
        "ANDROID_WEBVIEW_INTENT_LOADURL");
  }
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `./gradlew :benchmark:test --tests 'com.oversecured.sast.benchmark.FindingsArtifactReaderTest'`

Expected: FAIL with compilation error `cannot find symbol: class FindingsArtifactReader`.

- [ ] **Step 4: Implement artifact reader**

`FindingsArtifactReader.java`:

```java
package com.oversecured.sast.benchmark;

import com.oversecured.sast.common.Finding;
import com.oversecured.sast.common.FindingsDoc;
import com.oversecured.sast.common.Json;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

public final class FindingsArtifactReader {

  public List<Finding> readFindings(Path findingsDir) throws IOException {
    if (!Files.isDirectory(findingsDir)) {
      throw new IOException("findings directory does not exist: " + findingsDir);
    }
    List<Finding> out = new ArrayList<>();
    for (Path file : findingsFiles(findingsDir)) {
      FindingsDoc doc = Json.read(Files.readAllBytes(file), FindingsDoc.class);
      out.addAll(doc.findings());
    }
    return List.copyOf(out);
  }

  private List<Path> findingsFiles(Path dir) throws IOException {
    try (Stream<Path> stream = Files.list(dir)) {
      return stream
          .filter(Files::isRegularFile)
          .filter(p -> p.getFileName().toString().startsWith("findings"))
          .filter(p -> p.getFileName().toString().endsWith(".json"))
          .sorted(Comparator.comparing(p -> p.getFileName().toString()))
          .toList();
    }
  }
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `./gradlew :benchmark:test --tests 'com.oversecured.sast.benchmark.FindingsArtifactReaderTest'`

Expected: PASS (1 test).

- [ ] **Step 6: Commit**

```bash
git add benchmark/src/main/java/com/oversecured/sast/benchmark/FindingsArtifactReader.java benchmark/src/test/java/com/oversecured/sast/benchmark/FindingsArtifactReaderTest.java benchmark/src/test/resources/fixtures/findings
git commit -m "feat(benchmark): read findings artifacts via common json"
```

## Task 3: Pure finding matching and aggregate scoring

**Files:**
- Create: `benchmark/src/main/java/com/oversecured/sast/benchmark/FindingMatcher.java`
- Create: `benchmark/src/main/java/com/oversecured/sast/benchmark/ScoreCalculator.java`
- Modify: `benchmark/src/test/java/com/oversecured/sast/benchmark/ScoreCalculatorTest.java`

**Interfaces:**
- Consumes: common `Finding` objects and `ExpectedLeak` records.
- Produces: deterministic case and summary metrics.

- [ ] **Step 1: Extend the failing tests**

Add these tests to `ScoreCalculatorTest.java`:

```java
  @Test
  void scoresTruePositiveFalsePositiveAndFalseNegative() {
    ExpectedLeak webview = new ExpectedLeak(
        "ANDROID_WEBVIEW_INTENT_LOADURL", "WebViewActivity.java", 20, "loadUrl");
    ExpectedLeak traversal = new ExpectedLeak(
        "ANDROID_PATH_TRAVERSAL_PROVIDER", "TheftOverwriteProvider.java", 49, "ParcelFileDescriptor.open");
    FindingFingerprint matched = new FindingFingerprint(
        "ANDROID_WEBVIEW_INTENT_LOADURL", "WebViewActivity.java", 20, "sink: WebView.loadUrl(url)");
    FindingFingerprint unexpected = new FindingFingerprint(
        "ANDROID_WEBVIEW_INTENT_LOADURL", "InternalOnly.java", 12, "sink: WebView.loadUrl(url)");
    BenchmarkCase c = new BenchmarkCase(
        "ovaa", "ovaa", "ovaa", Path.of("app-debug.apk"), Path.of("ovaa"),
        List.of(webview, traversal), false, "");

    CaseScore score = new ScoreCalculator().score(c, List.of(matched, unexpected));

    assertThat(score.truePositives()).isEqualTo(1);
    assertThat(score.falsePositives()).isEqualTo(1);
    assertThat(score.falseNegatives()).isEqualTo(1);
    assertThat(score.precision()).isEqualTo(0.5d);
    assertThat(score.recall()).isEqualTo(0.5d);
    assertThat(score.f1()).isEqualTo(0.5d);
    assertThat(score.missedLeaks()).containsExactly(traversal);
  }

  @Test
  void aggregatesOnlyNonSkippedCases() {
    BenchmarkCase run = new BenchmarkCase(
        "droidbench", "GeneralJava", "MiniLeak", Path.of("a.apk"), Path.of("src"),
        List.of(new ExpectedLeak("R", "A.java", 1, "sink")), false, "");
    BenchmarkCase skipped = new BenchmarkCase(
        "droidbench", "Reflection", "Reflection1", Path.of("r.apk"), Path.of("src"),
        List.of(), true, "reflection is out of scope");
    CaseScore oneTp = new CaseScore(
        run, 1, 0, 0,
        List.of(new FindingFingerprint("R", "A.java", 1, "sink")),
        List.of(), List.of());

    ScoreSummary summary = new ScoreCalculator().summarize(
        "droidbench", List.of(oneTp), List.of(skipped), Path.of("score.json"), Path.of("score.md"));

    assertThat(summary.casesRun()).isEqualTo(1);
    assertThat(summary.casesSkipped()).isEqualTo(1);
    assertThat(summary.truePositives()).isEqualTo(1);
    assertThat(summary.precision()).isEqualTo(1.0d);
  }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./gradlew :benchmark:test --tests 'com.oversecured.sast.benchmark.ScoreCalculatorTest'`

Expected: FAIL with compilation errors for missing `ScoreCalculator`.

- [ ] **Step 3: Implement matcher and calculator**

`FindingMatcher.java`:

```java
package com.oversecured.sast.benchmark;

import com.oversecured.sast.common.Finding;
import com.oversecured.sast.common.FlowStep;
import java.nio.file.Path;

public final class FindingMatcher {

  public FindingFingerprint fingerprint(Finding finding) {
    FlowStep sink = finding.flow().isEmpty()
        ? new FlowStep("", 0, "")
        : finding.flow().get(finding.flow().size() - 1);
    String sinkFile = sink.file() == null ? "" : Path.of(sink.file()).getFileName().toString();
    return new FindingFingerprint(finding.ruleId(), sinkFile, sink.line(), sink.label());
  }

  public boolean matches(ExpectedLeak expected, FindingFingerprint actual) {
    if (!expected.ruleId().equals(actual.ruleId())) {
      return false;
    }
    if (!expected.sinkFile().equals(actual.sinkFile())) {
      return false;
    }
    if (expected.sinkLine() > 0 && expected.sinkLine() != actual.sinkLine()) {
      return false;
    }
    return actual.sinkLabel() != null && actual.sinkLabel().contains(expected.sinkLabelContains());
  }
}
```

`ScoreCalculator.java`:

```java
package com.oversecured.sast.benchmark;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class ScoreCalculator {

  private final FindingMatcher matcher = new FindingMatcher();

  public CaseScore score(BenchmarkCase benchmarkCase, List<FindingFingerprint> actualFindings) {
    Set<Integer> usedActual = new HashSet<>();
    List<FindingFingerprint> matched = new ArrayList<>();
    List<ExpectedLeak> missed = new ArrayList<>();

    for (ExpectedLeak expected : benchmarkCase.expectedLeaks()) {
      int index = firstUnusedMatch(expected, actualFindings, usedActual);
      if (index >= 0) {
        usedActual.add(index);
        matched.add(actualFindings.get(index));
      } else {
        missed.add(expected);
      }
    }

    List<FindingFingerprint> unexpected = new ArrayList<>();
    for (int i = 0; i < actualFindings.size(); i++) {
      if (!usedActual.contains(i)) {
        unexpected.add(actualFindings.get(i));
      }
    }

    return new CaseScore(
        benchmarkCase, matched.size(), unexpected.size(), missed.size(),
        List.copyOf(matched), List.copyOf(unexpected), List.copyOf(missed));
  }

  public ScoreSummary summarize(
      String suite, List<CaseScore> caseScores, List<BenchmarkCase> skippedCases,
      Path jsonSummary, Path markdownSummary) {
    int tp = caseScores.stream().mapToInt(CaseScore::truePositives).sum();
    int fp = caseScores.stream().mapToInt(CaseScore::falsePositives).sum();
    int fn = caseScores.stream().mapToInt(CaseScore::falseNegatives).sum();
    double precision = tp + fp == 0 ? 1.0d : ((double) tp) / (tp + fp);
    double recall = tp + fn == 0 ? 1.0d : ((double) tp) / (tp + fn);
    double f1 = precision + recall == 0.0d ? 0.0d : (2.0d * precision * recall) / (precision + recall);
    return new ScoreSummary(
        suite, caseScores.size(), skippedCases.size(), tp, fp, fn,
        precision, recall, f1, List.copyOf(caseScores), jsonSummary, markdownSummary);
  }

  private int firstUnusedMatch(ExpectedLeak expected, List<FindingFingerprint> actual, Set<Integer> used) {
    for (int i = 0; i < actual.size(); i++) {
      if (!used.contains(i) && matcher.matches(expected, actual.get(i))) {
        return i;
      }
    }
    return -1;
  }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `./gradlew :benchmark:test --tests 'com.oversecured.sast.benchmark.ScoreCalculatorTest'`

Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add benchmark/src/main/java/com/oversecured/sast/benchmark/FindingMatcher.java benchmark/src/main/java/com/oversecured/sast/benchmark/ScoreCalculator.java benchmark/src/test/java/com/oversecured/sast/benchmark/ScoreCalculatorTest.java
git commit -m "feat(benchmark): calculate precision recall and f1"
```

## Task 4: Parse DroidBench ground truth and catalog selected cases

**Files:**
- Create: `benchmark/src/main/java/com/oversecured/sast/benchmark/DroidBenchGroundTruthParser.java`
- Create: `benchmark/src/main/java/com/oversecured/sast/benchmark/DroidBenchCatalog.java`
- Create: `benchmark/src/test/resources/fixtures/droidbench/MiniLeak.java`
- Test: `benchmark/src/test/java/com/oversecured/sast/benchmark/DroidBenchGroundTruthParserTest.java`

**Interfaces:**
- Consumes: Java source files under `test-subjects/source/droidbench/`.
- Produces: expected leak records from `@number_of_leaks` plus `// sink, leak` comments, and a selected catalog that pairs source cases with prebuilt APKs.

- [ ] **Step 1: Write the fixture source**

`MiniLeak.java`:

```java
package de.ecspride;

/**
 * @number_of_leaks 1
 */
public class MiniLeak {
  public void test() {
    String secret = source(); // source
    sink(secret); // sink, leak
  }
}
```

- [ ] **Step 2: Write the failing tests**

`DroidBenchGroundTruthParserTest.java`:

```java
package com.oversecured.sast.benchmark;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class DroidBenchGroundTruthParserTest {

  @Test
  void parsesNumberOfLeaksAndSinkComment() throws Exception {
    Path file = Path.of("src/test/resources/fixtures/droidbench/MiniLeak.java").toAbsolutePath();
    List<ExpectedLeak> leaks = new DroidBenchGroundTruthParser()
        .parseCase("DROIDBENCH_GENERIC_LEAK", file.getParent());

    assertThat(leaks).containsExactly(new ExpectedLeak(
        "DROIDBENCH_GENERIC_LEAK", "MiniLeak.java", 9, "sink"));
  }

  @Test
  void classifiesOutOfScopeCategoriesAsSkipped() {
    DroidBenchCatalog catalog = new DroidBenchCatalog(
        Path.of("test-subjects/apk/droidbench"),
        Path.of("test-subjects/source/droidbench"));

    assertThat(catalog.isInScope("Reflection")).isFalse();
    assertThat(catalog.skipReason("Reflection")).isEqualTo("reflection is outside the challenge analysis scope");
    assertThat(catalog.isInScope("GeneralJava")).isTrue();
    assertThat(catalog.isInScope("Lifecycle")).isTrue();
    assertThat(catalog.isInScope("Callbacks")).isTrue();
    assertThat(catalog.isInScope("FieldAndObjectSensitivity")).isTrue();
    assertThat(catalog.isInScope("InterComponentCommunication")).isTrue();
  }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `./gradlew :benchmark:test --tests 'com.oversecured.sast.benchmark.DroidBenchGroundTruthParserTest'`

Expected: FAIL with compilation errors for missing `DroidBenchGroundTruthParser` and `DroidBenchCatalog`.

- [ ] **Step 4: Implement parser and catalog**

`DroidBenchGroundTruthParser.java`:

```java
package com.oversecured.sast.benchmark;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

public final class DroidBenchGroundTruthParser {

  private static final Pattern NUMBER_OF_LEAKS = Pattern.compile("@number_of_leaks\\s+(\\d+)");

  public List<ExpectedLeak> parseCase(String ruleId, Path caseSourceDir) throws IOException {
    List<ExpectedLeak> leaks = new ArrayList<>();
    int declaredLeakCount = 0;
    for (Path javaFile : javaFiles(caseSourceDir)) {
      List<String> lines = Files.readAllLines(javaFile);
      for (String line : lines) {
        Matcher matcher = NUMBER_OF_LEAKS.matcher(line);
        if (matcher.find()) {
          declaredLeakCount += Integer.parseInt(matcher.group(1));
        }
      }
      for (int i = 0; i < lines.size(); i++) {
        String line = lines.get(i);
        if (line.contains("// sink") && line.contains("leak")) {
          leaks.add(new ExpectedLeak(
              ruleId, javaFile.getFileName().toString(), i + 1, "sink"));
        }
      }
    }
    if (declaredLeakCount != leaks.size()) {
      throw new IOException("DroidBench leak count mismatch for " + caseSourceDir
          + ": declared=" + declaredLeakCount + " parsed=" + leaks.size());
    }
    return List.copyOf(leaks);
  }

  private List<Path> javaFiles(Path dir) throws IOException {
    try (Stream<Path> stream = Files.walk(dir)) {
      return stream
          .filter(Files::isRegularFile)
          .filter(p -> p.getFileName().toString().endsWith(".java"))
          .sorted(Comparator.comparing(Path::toString))
          .toList();
    }
  }
}
```

`DroidBenchCatalog.java`:

```java
package com.oversecured.sast.benchmark;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public final class DroidBenchCatalog {

  private static final Map<String, String> OUT_OF_SCOPE = Map.of(
      "Reflection", "reflection is outside the challenge analysis scope",
      "Reflection_ICC", "reflection is outside the challenge analysis scope",
      "ImplicitFlows", "implicit flows are outside the challenge analysis scope",
      "DynamicLoading", "dynamic loading is outside the challenge analysis scope",
      "Native", "native code is outside the challenge analysis scope",
      "Threading", "thread scheduling is outside the challenge analysis scope",
      "EmulatorDetection", "emulator-detection APIs are outside the target vulnerability classes",
      "InterAppCommunication", "full inter-app communication is outside the challenge analysis scope");

  private final Path apkRoot;
  private final Path sourceRoot;
  private final DroidBenchGroundTruthParser parser = new DroidBenchGroundTruthParser();

  public DroidBenchCatalog(Path apkRoot, Path sourceRoot) {
    this.apkRoot = apkRoot;
    this.sourceRoot = sourceRoot;
  }

  public boolean isInScope(String category) {
    return !OUT_OF_SCOPE.containsKey(category);
  }

  public String skipReason(String category) {
    return OUT_OF_SCOPE.getOrDefault(category, "");
  }

  public List<BenchmarkCase> discover(List<String> categories) throws IOException {
    List<BenchmarkCase> cases = new ArrayList<>();
    for (String category : categories) {
      Path categorySource = sourceRoot.resolve(category);
      Path categoryApk = apkRoot.resolve(category);
      if (!Files.isDirectory(categorySource)) {
        throw new IOException("missing DroidBench source category: " + categorySource);
      }
      try (var stream = Files.list(categorySource)) {
        for (Path caseDir : stream.filter(Files::isDirectory).sorted().toList()) {
          String name = caseDir.getFileName().toString();
          Path apk = categoryApk.resolve(name + ".apk");
          if (isInScope(category)) {
            cases.add(new BenchmarkCase(
                "droidbench", category, name, apk, caseDir,
                parser.parseCase("DROIDBENCH_GENERIC_LEAK", caseDir), false, ""));
          } else {
            cases.add(new BenchmarkCase(
                "droidbench", category, name, apk, caseDir, List.of(), true, skipReason(category)));
          }
        }
      }
    }
    return List.copyOf(cases);
  }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `./gradlew :benchmark:test --tests 'com.oversecured.sast.benchmark.DroidBenchGroundTruthParserTest'`

Expected: PASS (2 tests).

- [ ] **Step 6: Commit**

```bash
git add benchmark/src/main/java/com/oversecured/sast/benchmark/DroidBenchGroundTruthParser.java benchmark/src/main/java/com/oversecured/sast/benchmark/DroidBenchCatalog.java benchmark/src/test/java/com/oversecured/sast/benchmark/DroidBenchGroundTruthParserTest.java benchmark/src/test/resources/fixtures/droidbench/MiniLeak.java
git commit -m "feat(benchmark): parse droidbench ground truth"
```

## Task 5: OVAA expectation rules

**Files:**
- Create: `benchmark/src/main/java/com/oversecured/sast/benchmark/OvaaExpectation.java`
- Test: `benchmark/src/test/java/com/oversecured/sast/benchmark/OvaaExpectationTest.java`

**Interfaces:**
- Consumes: `FindingFingerprint` and common `Finding` data reduced to fingerprints.
- Produces: a strict OVAA target-set assertion with exactly two taint findings, allowed manifest findings, and no unexpected taint findings.

- [ ] **Step 1: Write the failing test**

`OvaaExpectationTest.java`:

```java
package com.oversecured.sast.benchmark;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import org.junit.jupiter.api.Test;

class OvaaExpectationTest {

  @Test
  void acceptsExactlyTwoRequiredTaintFindingsAndAllowedManifestFindings() {
    OvaaExpectation expectation = new OvaaExpectation();
    List<FindingFingerprint> findings = List.of(
        new FindingFingerprint("ANDROID_WEBVIEW_INTENT_LOADURL", "WebViewActivity.java", 20, "sink: WebView.loadUrl(url)"),
        new FindingFingerprint("ANDROID_PATH_TRAVERSAL_PROVIDER", "TheftOverwriteProvider.java", 49, "sink: ParcelFileDescriptor.open(file)"),
        new FindingFingerprint("exported_without_permission", "AndroidManifest.xml", 8, "exported activity"));

    CaseScore score = expectation.score(findings);

    assertThat(score.truePositives()).isEqualTo(2);
    assertThat(score.falsePositives()).isEqualTo(0);
    assertThat(score.falseNegatives()).isEqualTo(0);
    assertThat(score.precision()).isEqualTo(1.0d);
    assertThat(score.recall()).isEqualTo(1.0d);
  }

  @Test
  void rejectsUnexpectedTaintFindingAsFalsePositive() {
    OvaaExpectation expectation = new OvaaExpectation();
    List<FindingFingerprint> findings = List.of(
        new FindingFingerprint("ANDROID_WEBVIEW_INTENT_LOADURL", "WebViewActivity.java", 20, "sink: WebView.loadUrl(url)"),
        new FindingFingerprint("ANDROID_PATH_TRAVERSAL_PROVIDER", "TheftOverwriteProvider.java", 49, "sink: ParcelFileDescriptor.open(file)"),
        new FindingFingerprint("ANDROID_WEBVIEW_INTENT_LOADURL", "InternalOnly.java", 12, "sink: WebView.loadUrl(url)"));

    CaseScore score = expectation.score(findings);

    assertThat(score.falsePositives()).isEqualTo(1);
    assertThatThrownBy(() -> expectation.assertPassing(score))
        .hasMessageContaining("OVAA expected 0 false positives but got 1");
  }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :benchmark:test --tests 'com.oversecured.sast.benchmark.OvaaExpectationTest'`

Expected: FAIL with compilation error `cannot find symbol: class OvaaExpectation`.

- [ ] **Step 3: Implement OVAA expectation**

`OvaaExpectation.java`:

```java
package com.oversecured.sast.benchmark;

import java.nio.file.Path;
import java.util.List;
import java.util.Set;

public final class OvaaExpectation {

  private static final Set<String> ALLOWED_MANIFEST_RULE_IDS = Set.of(
      "exported_without_permission",
      "exported_provider",
      "provider_grant_uri_permissions",
      "weak_host_validation");

  private final BenchmarkCase benchmarkCase = new BenchmarkCase(
      "ovaa",
      "ovaa",
      "ovaa",
      Path.of("test-subjects/source/ovaa/app/build/outputs/apk/debug/app-debug.apk"),
      Path.of("test-subjects/source/ovaa"),
      List.of(
          new ExpectedLeak("ANDROID_WEBVIEW_INTENT_LOADURL", "WebViewActivity.java", 20, "loadUrl"),
          new ExpectedLeak("ANDROID_PATH_TRAVERSAL_PROVIDER", "TheftOverwriteProvider.java", 49, "ParcelFileDescriptor.open")),
      false,
      "");

  private final ScoreCalculator calculator = new ScoreCalculator();

  public CaseScore score(List<FindingFingerprint> actualFindings) {
    List<FindingFingerprint> scoreable = actualFindings.stream()
        .filter(f -> !ALLOWED_MANIFEST_RULE_IDS.contains(f.ruleId()))
        .toList();
    return calculator.score(benchmarkCase, scoreable);
  }

  public void assertPassing(CaseScore score) {
    if (score.truePositives() != 2) {
      throw new AssertionError("OVAA expected exactly 2 true positives but got " + score.truePositives());
    }
    if (score.falsePositives() != 0) {
      throw new AssertionError("OVAA expected 0 false positives but got " + score.falsePositives());
    }
    if (score.falseNegatives() != 0) {
      throw new AssertionError("OVAA expected 0 false negatives but got " + score.falseNegatives());
    }
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :benchmark:test --tests 'com.oversecured.sast.benchmark.OvaaExpectationTest'`

Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add benchmark/src/main/java/com/oversecured/sast/benchmark/OvaaExpectation.java benchmark/src/test/java/com/oversecured/sast/benchmark/OvaaExpectationTest.java
git commit -m "feat(benchmark): enforce ovaa expectations"
```

## Task 6: Black-box pipeline invocation and OVAA E2E runner

**Files:**
- Create: `benchmark/src/main/java/com/oversecured/sast/benchmark/CommandRunner.java`
- Create: `benchmark/src/main/java/com/oversecured/sast/benchmark/PipelineInvoker.java`
- Create: `benchmark/src/main/java/com/oversecured/sast/benchmark/GradlePipelineInvoker.java`
- Create: `benchmark/src/main/java/com/oversecured/sast/benchmark/BenchmarkPaths.java`
- Create: `benchmark/src/main/java/com/oversecured/sast/benchmark/OvaaBenchmark.java`
- Test: `benchmark/src/test/java/com/oversecured/sast/benchmark/OvaaExpectationTest.java` (add runner test with a fake invoker)

**Interfaces:**
- Consumes: existing root Gradle wrapper, OVAA Gradle project, and a pipeline entrypoint implemented by the orchestrator plan.
- Produces: `OvaaBenchmark.run()` that builds OVAA, invokes the pipeline, reads findings artifacts, scores them, and fails on mismatch.

- [ ] **Step 1: Add failing fake-runner test**

Add this method to `OvaaExpectationTest.java`:

```java
  @Test
  void ovaaBenchmarkScoresFindingsProducedByPipelineInvoker() throws Exception {
    java.nio.file.Path temp = java.nio.file.Files.createTempDirectory("ovaa-benchmark-test");
    java.nio.file.Path findings = temp.resolve("reports/findings");
    java.nio.file.Files.createDirectories(findings);
    java.nio.file.Files.copy(
        java.nio.file.Path.of("src/test/resources/fixtures/findings/findings-webview.json"),
        findings.resolve("findings-webview.json"));
    java.nio.file.Files.copy(
        java.nio.file.Path.of("src/test/resources/fixtures/findings/findings-pathtraversal.json"),
        findings.resolve("findings-pathtraversal.json"));

    PipelineInvoker invoker = (suite, apk, outDir) -> temp;
    CommandRunner runner = command -> new CommandRunner.Result(0, "BUILD SUCCESSFUL", "");
    OvaaBenchmark benchmark = new OvaaBenchmark(
        new BenchmarkPaths(java.nio.file.Path.of("").toAbsolutePath()), runner, invoker);

    CaseScore score = benchmark.run(temp.resolve("summary"));

    assertThat(score.truePositives()).isEqualTo(2);
    assertThat(score.falsePositives()).isEqualTo(0);
    assertThat(score.falseNegatives()).isEqualTo(0);
  }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :benchmark:test --tests 'com.oversecured.sast.benchmark.OvaaExpectationTest.ovaaBenchmarkScoresFindingsProducedByPipelineInvoker'`

Expected: FAIL with compilation errors for missing `PipelineInvoker`, `CommandRunner`, `BenchmarkPaths`, and `OvaaBenchmark`.

- [ ] **Step 3: Implement black-box runner**

`CommandRunner.java`:

```java
package com.oversecured.sast.benchmark;

import java.io.IOException;
import java.util.List;

@FunctionalInterface
public interface CommandRunner {
  Result run(List<String> command) throws IOException, InterruptedException;

  record Result(int exitCode, String stdout, String stderr) {}

  static CommandRunner process() {
    return command -> {
      Process process = new ProcessBuilder(command).redirectErrorStream(false).start();
      String stdout = new String(process.getInputStream().readAllBytes());
      String stderr = new String(process.getErrorStream().readAllBytes());
      int exit = process.waitFor();
      return new Result(exit, stdout, stderr);
    };
  }
}
```

`PipelineInvoker.java`:

```java
package com.oversecured.sast.benchmark;

import java.io.IOException;
import java.nio.file.Path;

@FunctionalInterface
public interface PipelineInvoker {
  Path runPipeline(String suite, Path apk, Path outDir) throws IOException, InterruptedException;
}
```

`BenchmarkPaths.java`:

```java
package com.oversecured.sast.benchmark;

import java.nio.file.Path;

public record BenchmarkPaths(Path repoRoot) {
  public Path ovaaSourceDir() {
    return repoRoot.resolve("test-subjects/source/ovaa");
  }

  public Path ovaaApk() {
    return ovaaSourceDir().resolve("app/build/outputs/apk/debug/app-debug.apk");
  }

  public Path droidBenchApkRoot() {
    return repoRoot.resolve("test-subjects/apk/droidbench");
  }

  public Path droidBenchSourceRoot() {
    return repoRoot.resolve("test-subjects/source/droidbench");
  }

  public Path defaultBenchmarkOutput(String suite) {
    return repoRoot.resolve("benchmark/build/reports/benchmark").resolve(suite);
  }
}
```

`GradlePipelineInvoker.java`:

```java
package com.oversecured.sast.benchmark;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

public final class GradlePipelineInvoker implements PipelineInvoker {

  private final Path repoRoot;
  private final CommandRunner commandRunner;

  public GradlePipelineInvoker(Path repoRoot, CommandRunner commandRunner) {
    this.repoRoot = repoRoot;
    this.commandRunner = commandRunner;
  }

  @Override
  public Path runPipeline(String suite, Path apk, Path outDir) throws IOException, InterruptedException {
    Path runDir = outDir.resolve("runs").resolve(suite);
    List<String> command = List.of(
        repoRoot.resolve("gradlew").toString(),
        ":orchestrator:runPipeline",
        "--args=--apk " + apk.toAbsolutePath()
            + " --rules " + repoRoot.resolve("rules").toAbsolutePath()
            + " --out " + runDir.toAbsolutePath());
    CommandRunner.Result result = commandRunner.run(command);
    if (result.exitCode() != 0) {
      throw new IOException("pipeline failed with exit " + result.exitCode() + "\n" + result.stderr());
    }
    return runDir;
  }
}
```

`OvaaBenchmark.java`:

```java
package com.oversecured.sast.benchmark;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

public final class OvaaBenchmark {

  private final BenchmarkPaths paths;
  private final CommandRunner commandRunner;
  private final PipelineInvoker pipelineInvoker;
  private final FindingsArtifactReader findingsReader = new FindingsArtifactReader();
  private final FindingMatcher matcher = new FindingMatcher();
  private final OvaaExpectation expectation = new OvaaExpectation();

  public OvaaBenchmark(BenchmarkPaths paths, CommandRunner commandRunner, PipelineInvoker pipelineInvoker) {
    this.paths = paths;
    this.commandRunner = commandRunner;
    this.pipelineInvoker = pipelineInvoker;
  }

  public CaseScore run(Path outDir) throws IOException, InterruptedException {
    buildOvaaApk();
    Path runDir = pipelineInvoker.runPipeline("ovaa", paths.ovaaApk(), outDir);
    List<FindingFingerprint> fingerprints = findingsReader
        .readFindings(runDir.resolve("reports/findings"))
        .stream()
        .map(matcher::fingerprint)
        .toList();
    CaseScore score = expectation.score(fingerprints);
    expectation.assertPassing(score);
    return score;
  }

  private void buildOvaaApk() throws IOException, InterruptedException {
    CommandRunner.Result result = commandRunner.run(List.of(
        paths.ovaaSourceDir().resolve("gradlew").toString(),
        "-p", paths.ovaaSourceDir().toString(),
        "assembleDebug"));
    if (result.exitCode() != 0) {
      throw new IOException("OVAA assembleDebug failed with exit " + result.exitCode() + "\n" + result.stderr());
    }
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :benchmark:test --tests 'com.oversecured.sast.benchmark.OvaaExpectationTest.ovaaBenchmarkScoresFindingsProducedByPipelineInvoker'`

Expected: PASS (1 test).

- [ ] **Step 5: Manual E2E verification command**

Run after the orchestrator plan has implemented `:orchestrator:runPipeline`:

```bash
./gradlew :benchmark:test --tests 'com.oversecured.sast.benchmark.OvaaExpectationTest'
./gradlew :benchmark:runBenchmark --args='ovaa --out benchmark/build/reports/benchmark/ovaa'
```

Expected: `BUILD SUCCESSFUL`; `benchmark/build/reports/benchmark/ovaa/reports/findings/` contains the pipeline's `findings*.json`; OVAA score has TP=2, FP=0, FN=0.

- [ ] **Step 6: Commit**

```bash
git add benchmark/src/main/java/com/oversecured/sast/benchmark/CommandRunner.java benchmark/src/main/java/com/oversecured/sast/benchmark/PipelineInvoker.java benchmark/src/main/java/com/oversecured/sast/benchmark/GradlePipelineInvoker.java benchmark/src/main/java/com/oversecured/sast/benchmark/BenchmarkPaths.java benchmark/src/main/java/com/oversecured/sast/benchmark/OvaaBenchmark.java benchmark/src/test/java/com/oversecured/sast/benchmark/OvaaExpectationTest.java
git commit -m "feat(benchmark): run ovaa as black-box e2e validation"
```

## Task 7: DroidBench benchmark runner

**Files:**
- Create: `benchmark/src/main/java/com/oversecured/sast/benchmark/DroidBenchBenchmark.java`
- Test: `benchmark/src/test/java/com/oversecured/sast/benchmark/DroidBenchBenchmarkTest.java`

**Interfaces:**
- Consumes: `DroidBenchCatalog`, `PipelineInvoker`, `FindingsArtifactReader`, `ScoreCalculator`.
- Produces: aggregate DroidBench score for selected categories with skipped out-of-scope cases represented in the summary.

- [ ] **Step 1: Write the failing test**

`DroidBenchBenchmarkTest.java`:

```java
package com.oversecured.sast.benchmark;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class DroidBenchBenchmarkTest {

  @Test
  void runsNonSkippedCasesAndAggregatesScore() throws Exception {
    Path temp = Files.createTempDirectory("droidbench-benchmark-test");
    Path apkRoot = Files.createDirectories(temp.resolve("apk/GeneralJava"));
    Path sourceRoot = Files.createDirectories(temp.resolve("source/GeneralJava/MiniLeak"));
    Files.writeString(apkRoot.resolve("MiniLeak.apk"), "fake apk");
    Files.copy(
        Path.of("src/test/resources/fixtures/droidbench/MiniLeak.java"),
        sourceRoot.resolve("MiniLeak.java"));

    PipelineInvoker invoker = (suite, apk, outDir) -> {
      Path runDir = Files.createDirectories(outDir.resolve("runs").resolve(suite));
      Path findings = Files.createDirectories(runDir.resolve("reports/findings"));
      Files.copy(
          Path.of("src/test/resources/fixtures/findings/findings-webview.json"),
          findings.resolve("findings-webview.json"));
      return runDir;
    };

    DroidBenchBenchmark benchmark = new DroidBenchBenchmark(
        new DroidBenchCatalog(temp.resolve("apk"), temp.resolve("source")), invoker);

    ScoreSummary summary = benchmark.run(List.of("GeneralJava"), temp.resolve("out"));

    assertThat(summary.casesRun()).isEqualTo(1);
    assertThat(summary.truePositives()).isEqualTo(0);
    assertThat(summary.falsePositives()).isEqualTo(1);
    assertThat(summary.falseNegatives()).isEqualTo(1);
  }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :benchmark:test --tests 'com.oversecured.sast.benchmark.DroidBenchBenchmarkTest'`

Expected: FAIL with compilation error `cannot find symbol: class DroidBenchBenchmark`.

- [ ] **Step 3: Implement DroidBench benchmark runner**

`DroidBenchBenchmark.java`:

```java
package com.oversecured.sast.benchmark;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public final class DroidBenchBenchmark {

  private final DroidBenchCatalog catalog;
  private final PipelineInvoker pipelineInvoker;
  private final FindingsArtifactReader findingsReader = new FindingsArtifactReader();
  private final FindingMatcher matcher = new FindingMatcher();
  private final ScoreCalculator calculator = new ScoreCalculator();

  public DroidBenchBenchmark(DroidBenchCatalog catalog, PipelineInvoker pipelineInvoker) {
    this.catalog = catalog;
    this.pipelineInvoker = pipelineInvoker;
  }

  public ScoreSummary run(List<String> categories, Path outDir) throws IOException, InterruptedException {
    List<BenchmarkCase> cases = catalog.discover(categories);
    List<CaseScore> scores = new ArrayList<>();
    List<BenchmarkCase> skipped = new ArrayList<>();
    for (BenchmarkCase benchmarkCase : cases) {
      if (benchmarkCase.skipped()) {
        skipped.add(benchmarkCase);
        continue;
      }
      Path runDir = pipelineInvoker.runPipeline(
          "droidbench-" + benchmarkCase.category() + "-" + benchmarkCase.name(),
          benchmarkCase.apk(),
          outDir);
      List<FindingFingerprint> actual = findingsReader
          .readFindings(runDir.resolve("reports/findings"))
          .stream()
          .map(matcher::fingerprint)
          .toList();
      scores.add(calculator.score(benchmarkCase, actual));
    }
    return calculator.summarize(
        "droidbench", scores, skipped,
        outDir.resolve("summary.json"), outDir.resolve("summary.md"));
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :benchmark:test --tests 'com.oversecured.sast.benchmark.DroidBenchBenchmarkTest'`

Expected: PASS (1 test).

- [ ] **Step 5: Manual DroidBench smoke command**

Run after the decompiler/parser/manifest-facts/taint/orchestrator pipeline is executable:

```bash
./gradlew :benchmark:runBenchmark --args='droidbench --categories GeneralJava --out benchmark/build/reports/benchmark/droidbench'
```

Expected: `BUILD SUCCESSFUL`; summary includes `casesRun > 0`, TP/FP/FN totals, precision/recall/F1, and no skipped cases for `GeneralJava`.

- [ ] **Step 6: Commit**

```bash
git add benchmark/src/main/java/com/oversecured/sast/benchmark/DroidBenchBenchmark.java benchmark/src/test/java/com/oversecured/sast/benchmark/DroidBenchBenchmarkTest.java
git commit -m "feat(benchmark): score selected droidbench cases"
```

## Task 8: JSON and Markdown summary writer

**Files:**
- Create: `benchmark/src/main/java/com/oversecured/sast/benchmark/BenchmarkReportWriter.java`
- Test: `benchmark/src/test/java/com/oversecured/sast/benchmark/BenchmarkReportWriterTest.java`

**Interfaces:**
- Consumes: `ScoreSummary` and common `Json`.
- Produces: deterministic `summary.json` and `summary.md` files for OVAA and DroidBench.

- [ ] **Step 1: Write the failing test**

`BenchmarkReportWriterTest.java`:

```java
package com.oversecured.sast.benchmark;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class BenchmarkReportWriterTest {

  @Test
  void writesJsonAndMarkdownSummaries() throws Exception {
    Path temp = Files.createTempDirectory("benchmark-report-writer-test");
    BenchmarkCase c = new BenchmarkCase(
        "ovaa", "ovaa", "ovaa", Path.of("app-debug.apk"), Path.of("ovaa"),
        List.of(new ExpectedLeak("R", "A.java", 1, "sink")), false, "");
    CaseScore score = new CaseScore(
        c, 1, 0, 0,
        List.of(new FindingFingerprint("R", "A.java", 1, "sink")),
        List.of(), List.of());
    ScoreSummary summary = new ScoreSummary(
        "ovaa", 1, 0, 1, 0, 0, 1.0d, 1.0d, 1.0d,
        List.of(score), temp.resolve("summary.json"), temp.resolve("summary.md"));

    new BenchmarkReportWriter().write(summary);

    assertThat(Files.readString(temp.resolve("summary.json"))).contains("\"suite\" : \"ovaa\"");
    assertThat(Files.readString(temp.resolve("summary.md"))).contains("| Suite | Cases Run | TP | FP | FN | Precision | Recall | F1 |");
    assertThat(Files.readString(temp.resolve("summary.md"))).contains("| ovaa | 1 | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |");
  }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :benchmark:test --tests 'com.oversecured.sast.benchmark.BenchmarkReportWriterTest'`

Expected: FAIL with compilation error `cannot find symbol: class BenchmarkReportWriter`.

- [ ] **Step 3: Implement writer**

`BenchmarkReportWriter.java`:

```java
package com.oversecured.sast.benchmark;

import com.oversecured.sast.common.Json;
import java.io.IOException;
import java.nio.file.Files;

public final class BenchmarkReportWriter {

  public void write(ScoreSummary summary) throws IOException {
    Files.createDirectories(summary.jsonSummary().getParent());
    Files.createDirectories(summary.markdownSummary().getParent());
    Files.write(summary.jsonSummary(), Json.writeBytes(summary));
    Files.writeString(summary.markdownSummary(), markdown(summary));
  }

  private String markdown(ScoreSummary summary) {
    StringBuilder sb = new StringBuilder();
    sb.append("# ").append(summary.suite()).append(" benchmark summary\n\n");
    sb.append("| Suite | Cases Run | TP | FP | FN | Precision | Recall | F1 |\n");
    sb.append("|---|---:|---:|---:|---:|---:|---:|---:|\n");
    sb.append("| ").append(summary.suite())
        .append(" | ").append(summary.casesRun())
        .append(" | ").append(summary.truePositives())
        .append(" | ").append(summary.falsePositives())
        .append(" | ").append(summary.falseNegatives())
        .append(" | ").append(String.format(java.util.Locale.ROOT, "%.3f", summary.precision()))
        .append(" | ").append(String.format(java.util.Locale.ROOT, "%.3f", summary.recall()))
        .append(" | ").append(String.format(java.util.Locale.ROOT, "%.3f", summary.f1()))
        .append(" |\n\n");
    sb.append("Skipped cases: ").append(summary.casesSkipped()).append("\n");
    return sb.toString();
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :benchmark:test --tests 'com.oversecured.sast.benchmark.BenchmarkReportWriterTest'`

Expected: PASS (1 test).

- [ ] **Step 5: Commit**

```bash
git add benchmark/src/main/java/com/oversecured/sast/benchmark/BenchmarkReportWriter.java benchmark/src/test/java/com/oversecured/sast/benchmark/BenchmarkReportWriterTest.java
git commit -m "feat(benchmark): write json and markdown summaries"
```

## Task 9: CLI and Gradle benchmark tasks

**Files:**
- Create: `benchmark/src/main/java/com/oversecured/sast/benchmark/BenchmarkCli.java`
- Modify: `benchmark/build.gradle`
- Test: `benchmark/src/test/java/com/oversecured/sast/benchmark/BenchmarkCliTest.java`

**Interfaces:**
- Consumes: `OvaaBenchmark`, `DroidBenchBenchmark`, `BenchmarkReportWriter`.
- Produces:
  - `./gradlew :benchmark:runBenchmark --args='ovaa --out benchmark/build/reports/benchmark/ovaa'`
  - `./gradlew :benchmark:runBenchmark --args='droidbench --categories GeneralJava,Lifecycle,Callbacks,FieldAndObjectSensitivity,InterComponentCommunication --out benchmark/build/reports/benchmark/droidbench'`
  - `./gradlew :benchmark:verifyOvaa`
  - `./gradlew :benchmark:scoreDroidBench`

- [ ] **Step 1: Write the failing CLI test**

`BenchmarkCliTest.java`:

```java
package com.oversecured.sast.benchmark;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import picocli.CommandLine;

class BenchmarkCliTest {

  @Test
  void exposesOvaaAndDroidBenchSubcommands() {
    CommandLine cli = new CommandLine(new BenchmarkCli());

    assertThat(cli.getSubcommands().keySet()).contains("ovaa", "droidbench", "score-artifacts");
  }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :benchmark:test --tests 'com.oversecured.sast.benchmark.BenchmarkCliTest'`

Expected: FAIL with compilation error `cannot find symbol: class BenchmarkCli`.

- [ ] **Step 3: Implement CLI**

`BenchmarkCli.java`:

```java
package com.oversecured.sast.benchmark;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(
    name = "benchmark",
    mixinStandardHelpOptions = true,
    subcommands = {
        BenchmarkCli.OvaaCommand.class,
        BenchmarkCli.DroidBenchCommand.class,
        BenchmarkCli.ScoreArtifactsCommand.class
    })
public final class BenchmarkCli implements Runnable {

  public static void main(String[] args) {
    int exit = new CommandLine(new BenchmarkCli()).execute(args);
    System.exit(exit);
  }

  @Override
  public void run() {
    new CommandLine(this).usage(System.out);
  }

  @Command(name = "ovaa", mixinStandardHelpOptions = true)
  static final class OvaaCommand implements Callable<Integer> {
    @Option(names = "--out", required = true)
    Path out;

    @Override
    public Integer call() throws Exception {
      Path repo = Path.of("").toAbsolutePath();
      BenchmarkPaths paths = new BenchmarkPaths(repo);
      Path outDir = out.toAbsolutePath();
      OvaaBenchmark benchmark = new OvaaBenchmark(
          paths,
          CommandRunner.process(),
          new GradlePipelineInvoker(repo, CommandRunner.process()));
      CaseScore score = benchmark.run(outDir);
      ScoreSummary summary = new ScoreCalculator().summarize(
          "ovaa", List.of(score), List.of(), outDir.resolve("summary.json"), outDir.resolve("summary.md"));
      new BenchmarkReportWriter().write(summary);
      return 0;
    }
  }

  @Command(name = "droidbench", mixinStandardHelpOptions = true)
  static final class DroidBenchCommand implements Callable<Integer> {
    @Option(names = "--categories", required = true, split = ",")
    List<String> categories;

    @Option(names = "--out", required = true)
    Path out;

    @Override
    public Integer call() throws Exception {
      Path repo = Path.of("").toAbsolutePath();
      BenchmarkPaths paths = new BenchmarkPaths(repo);
      DroidBenchBenchmark benchmark = new DroidBenchBenchmark(
          new DroidBenchCatalog(paths.droidBenchApkRoot(), paths.droidBenchSourceRoot()),
          new GradlePipelineInvoker(repo, CommandRunner.process()));
      ScoreSummary summary = benchmark.run(categories, out.toAbsolutePath());
      new BenchmarkReportWriter().write(summary);
      return summary.falsePositives() == 0 ? 0 : 2;
    }
  }

  @Command(name = "score-artifacts", mixinStandardHelpOptions = true)
  static final class ScoreArtifactsCommand implements Callable<Integer> {
    @Option(names = "--suite", required = true)
    String suite;

    @Option(names = "--findings", required = true)
    Path findings;

    @Option(names = "--out", required = true)
    Path out;

    @Override
    public Integer call() throws Exception {
      FindingMatcher matcher = new FindingMatcher();
      List<FindingFingerprint> fingerprints = new FindingsArtifactReader()
          .readFindings(findings.toAbsolutePath()).stream().map(matcher::fingerprint).toList();
      CaseScore score = new OvaaExpectation().score(fingerprints);
      ScoreSummary summary = new ScoreCalculator().summarize(
          suite, List.of(score), List.of(), out.resolve("summary.json"), out.resolve("summary.md"));
      new BenchmarkReportWriter().write(summary);
      return summary.falsePositives() == 0 && summary.falseNegatives() == 0 ? 0 : 2;
    }
  }
}
```

Modify `benchmark/build.gradle`:

```groovy
plugins {
    id 'java-library'
}

dependencies {
    api project(':common')
    implementation "info.picocli:picocli:${rootProject.ext.picocliVersion}"
    annotationProcessor "info.picocli:picocli-codegen:${rootProject.ext.picocliVersion}"
}

tasks.register('runBenchmark', JavaExec) {
    group = 'verification'
    description = 'Runs benchmark CLI. Pass subcommand args with --args.'
    classpath = sourceSets.main.runtimeClasspath
    mainClass = 'com.oversecured.sast.benchmark.BenchmarkCli'
}

tasks.register('verifyOvaa', JavaExec) {
    group = 'verification'
    description = 'Builds OVAA, runs the full pipeline, and verifies exact expected findings.'
    classpath = sourceSets.main.runtimeClasspath
    mainClass = 'com.oversecured.sast.benchmark.BenchmarkCli'
    args 'ovaa', '--out', "${projectDir}/build/reports/benchmark/ovaa"
}

tasks.register('scoreDroidBench', JavaExec) {
    group = 'verification'
    description = 'Runs the selected in-scope DroidBench benchmark set and writes score summaries.'
    classpath = sourceSets.main.runtimeClasspath
    mainClass = 'com.oversecured.sast.benchmark.BenchmarkCli'
    args 'droidbench',
        '--categories', 'GeneralJava,Lifecycle,Callbacks,FieldAndObjectSensitivity,InterComponentCommunication',
        '--out', "${projectDir}/build/reports/benchmark/droidbench"
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `./gradlew :benchmark:test --tests 'com.oversecured.sast.benchmark.BenchmarkCliTest'`

Expected: PASS (1 test).

- [ ] **Step 5: Verify Gradle task discovery**

Run: `./gradlew :benchmark:tasks --group verification`

Expected: output includes `runBenchmark`, `verifyOvaa`, and `scoreDroidBench`.

- [ ] **Step 6: Commit**

```bash
git add benchmark/build.gradle benchmark/src/main/java/com/oversecured/sast/benchmark/BenchmarkCli.java benchmark/src/test/java/com/oversecured/sast/benchmark/BenchmarkCliTest.java
git commit -m "feat(benchmark): expose benchmark cli and gradle tasks"
```

## Task 10: Final verification commands

**Files:**
- No new files.

**Interfaces:**
- Verifies: all benchmark tests, black-box artifact scoring, OVAA E2E, and DroidBench scoring after sibling pipeline modules exist.

- [ ] **Step 1: Run benchmark unit tests**

Run:

```bash
./gradlew :benchmark:test
```

Expected: PASS; all `com.oversecured.sast.benchmark.*` tests pass.

- [ ] **Step 2: Score existing fixture artifacts without running pipeline**

Run:

```bash
./gradlew :benchmark:runBenchmark --args='score-artifacts --suite ovaa --findings benchmark/src/test/resources/fixtures/findings --out benchmark/build/reports/benchmark/artifact-smoke'
```

Expected: PASS; `benchmark/build/reports/benchmark/artifact-smoke/summary.json` and `summary.md` exist; summary has TP=2, FP=0, FN=0.

- [ ] **Step 3: Run OVAA E2E**

Run:

```bash
./gradlew :benchmark:verifyOvaa
```

Expected: PASS after sibling modules are implemented. OVAA is built by `test-subjects/source/ovaa/gradlew assembleDebug`; summary JSON contains `"truePositives" : 2`, `"falsePositives" : 0`, `"falseNegatives" : 0`.

- [ ] **Step 4: Run DroidBench scoring harness**

Run:

```bash
./gradlew :benchmark:scoreDroidBench
```

Expected: PASS when selected in-scope cases are supported by the pipeline; `benchmark/build/reports/benchmark/droidbench/summary.json` and `summary.md` contain TP/FP/FN, precision, recall, F1, and per-case scores. If a selected case is not yet supported by the taint engine, the command exits non-zero with explicit false positives or false negatives in `summary.json`.

- [ ] **Step 5: Commit any final fixes**

```bash
git add benchmark
git commit -m "test(benchmark): verify e2e benchmark harness"
```

## Self-Review Checklist

**Spec coverage:** OVAA builds via `./gradlew assembleDebug`, runs pipeline black-box, requires exactly 2 taint findings and 0 false positives. DroidBench scoring covers TP/FP/FN and precision/recall/F1. JSON and Markdown summaries are produced by CLI/Gradle tasks. Common `FindingsDoc`, `Finding`, and `Json` are consumed directly.

**Boundary check:** The plan adds no analyzer logic to `benchmark`; all execution goes through `PipelineInvoker` and artifact reads. The only matching logic is benchmark scoring against expected outputs.

**Fixture consistency:** Source inputs stay under `test-subjects/`; generated benchmark output stays under `benchmark/build/reports/benchmark/`.

**Commands:** Every task uses `./gradlew` for repo verification, except OVAA's internal build, which is invoked by `OvaaBenchmark` as `test-subjects/source/ovaa/gradlew -p test-subjects/source/ovaa assembleDebug`.
