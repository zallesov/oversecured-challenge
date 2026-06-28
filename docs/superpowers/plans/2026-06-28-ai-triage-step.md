# AI Triage Step Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an in-process AI triage pipeline step that reads the SARIF report plus decompiled source in a LangChain4j tool-calling loop and writes a sidecar analysis (`ai-triage.json` + `ai-triage.md`) judging each finding's verdict, severity, and fix.

**Architecture:** A new Gradle module `apps/ai-triage` holds the agent (SARIF parsing, path-jailed source tools, LangChain4j `AiServices` over an OpenAI-compatible OpenRouter model, JSON/Markdown rendering). The orchestrator gains one in-process Temporal activity `aiTriage`, wired into the workflow after `report`. The step is always-on and fail-soft: a missing API key or any error yields an empty sidecar and a successful workflow.

**Tech Stack:** Java 17, Gradle, LangChain4j (`langchain4j` + `langchain4j-open-ai`), Jackson, Temporal, JUnit 5 + AssertJ.

## Global Constraints

- Java toolchain: **17** (root `build.gradle` sets `JavaLanguageVersion.of(17)` for all subprojects).
- LangChain4j version pinned in root `build.gradle` ext: **`langchain4jVersion = '1.1.0'`**. Artifacts `dev.langchain4j:langchain4j:1.1.0` and `dev.langchain4j:langchain4j-open-ai:1.1.0`.
- Jackson version via existing ext: `${rootProject.ext.jacksonVersion}` (`2.17.1`).
- Test deps (`junit-jupiter`, `assertj-core`) are injected by the root `subprojects` block — do NOT re-declare them in module `build.gradle`.
- **This branch has uncommitted WIP** (the `status/StepResult` refactor): activities return `com.oversecured.sast.orchestrator.status.StepResult` via `StepResult.completed(nodeId, message, metrics, artifacts, findingsKeys, findingCount, severityCounts)`. Build on the current working tree; do not revert it.
- Fail-soft is mandatory: `AiTriageAnalyzer.run` MUST NOT throw. All errors → empty sidecar + return.
- No network calls in any test. The production LangChain4j model is only built, never invoked, in tests.
- Verdict vocabulary is exactly `exploitable` / `needs-review` / `safe`. Severity is exactly `critical` / `high` / `medium` / `low` / `info`.
- Env vars: `OPENROUTER_API_KEY` (required at runtime; absence triggers fail-soft skip), `OPENROUTER_MODEL` (optional; default `anthropic/claude-3.5-sonnet`).

---

## File Structure

New module `apps/ai-triage`, package `com.oversecured.sast.aitriage`:

- `FindingRef.java` — `(String ruleId, String file, int line)`.
- `TriageFlowStep.java` — `(String file, int line, String label)`.
- `TriageFinding.java` — parsed SARIF finding + its `FindingRef`.
- `Verdict.java` — enum `EXPLOITABLE|NEEDS_REVIEW|SAFE`, JSON values `exploitable|needs-review|safe`.
- `TriageSeverity.java` — enum `CRITICAL|HIGH|MEDIUM|LOW|INFO`, lowercase JSON.
- `TriageItem.java` / `TriageResult.java` — structured-output + artifact shape.
- `SarifFindings.java` — SARIF → `List<TriageFinding>`.
- `SourceTools.java` — `@Tool` path-jailed source readers.
- `TriagePrompt.java` — `static final String SYSTEM` + `renderFindings(...)`.
- `MarkdownRenderer.java` — `TriageResult` → markdown.
- `TriageJson.java` — `TriageResult` ↔ JSON (Jackson, lowercase enums).
- `TriageEngine.java` — `interface { TriageResult triage(List<TriageFinding>); String modelName(); }`.
- `TriageEngineFactory.java` — `interface { TriageEngine create(Path sourcesDir); }` (returns `null` when unavailable).
- `LangChainTriageEngine.java` — production `TriageEngine` + static `create(apiKey, baseUrl, model, sourcesDir)`.
- `AiTriageAnalyzer.java` — orchestrates parse → engine → write; owns fail-soft.

Orchestrator changes (package `...orchestrator`):

- `activities/AiTriageActivityInput.java` — new.
- `activities/PipelineActivities.java` — `+ StepResult aiTriage(...)`.
- `activities/PipelineActivitiesImpl.java` — `+ aiTriage` impl, `+ StepApis.aiTriage`, `+ ProductionStepApis.aiTriage`.
- `workflow/AnalyzeApkWorkflowImpl.java` — `+ AI_TRIAGE` node + `runStep` after report + node def.
- `AnalysisResult.java` — `+ aiTriageJsonKey, aiTriageMdKey`.
- `AnalysisPlan.java` (`ReportConfig`) — `+ aiTriageJsonKey, aiTriageMdKey`.
- `cli/StartAnalysisCommand.java` — print new keys.
- `build.gradle` / `settings.gradle` — module wiring.

---

### Task 1: Module scaffold + domain records

**Files:**
- Modify: `settings.gradle`
- Modify: `build.gradle` (root, ext block)
- Create: `apps/ai-triage/build.gradle`
- Create: `apps/ai-triage/src/main/java/com/oversecured/sast/aitriage/FindingRef.java`
- Create: `.../TriageFlowStep.java`, `.../TriageFinding.java`, `.../Verdict.java`, `.../TriageSeverity.java`, `.../TriageItem.java`, `.../TriageResult.java`
- Test: `apps/ai-triage/src/test/java/com/oversecured/sast/aitriage/TriageResultTest.java`

**Interfaces:**
- Produces: the records/enums above. Field order is normative for later tasks:
  - `FindingRef(String ruleId, String file, int line)`
  - `TriageFlowStep(String file, int line, String label)`
  - `TriageFinding(String ruleId, String level, String message, String cwe, String owaspMobile, List<TriageFlowStep> flow, FindingRef ref)`
  - `Verdict { EXPLOITABLE("exploitable"), NEEDS_REVIEW("needs-review"), SAFE("safe") }` with `@JsonValue String json()`
  - `TriageSeverity { CRITICAL, HIGH, MEDIUM, LOW, INFO }` with `@JsonValue` lowercase
  - `TriageItem(FindingRef ref, Verdict verdict, TriageSeverity severity, double confidence, String rationale, String fix, List<String> references)`
  - `TriageResult(String model, String generatedAt, String summary, List<TriageItem> items)`

- [ ] **Step 1: Add module to settings.gradle**

In `settings.gradle`, add after `include 'apps:reporter'`:

```gradle
include 'apps:ai-triage'
```

- [ ] **Step 2: Add LangChain4j version to root ext**

In root `build.gradle`, inside the `ext { ... }` block, add:

```gradle
    langchain4jVersion = '1.1.0'
```

- [ ] **Step 3: Create module build.gradle**

`apps/ai-triage/build.gradle`:

```gradle
plugins {
    id 'java-library'
}

dependencies {
    implementation project(':common')
    implementation "com.fasterxml.jackson.core:jackson-databind:${rootProject.ext.jacksonVersion}"
    implementation "dev.langchain4j:langchain4j:${rootProject.ext.langchain4jVersion}"
    implementation "dev.langchain4j:langchain4j-open-ai:${rootProject.ext.langchain4jVersion}"
}
```

- [ ] **Step 4: Write the failing test**

`apps/ai-triage/src/test/java/com/oversecured/sast/aitriage/TriageResultTest.java`:

```java
package com.oversecured.sast.aitriage;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class TriageResultTest {

    @Test
    void holdsItemsAndEnumsExposeJsonValues() {
        TriageItem item = new TriageItem(
                new FindingRef("RULE", "A.java", 47),
                Verdict.NEEDS_REVIEW,
                TriageSeverity.HIGH,
                0.8,
                "why",
                "fix",
                List.of("CWE-601"));
        TriageResult result = new TriageResult("m", "2026-06-28T00:00:00Z", "summary", List.of(item));

        assertThat(result.items()).hasSize(1);
        assertThat(result.items().get(0).ref().line()).isEqualTo(47);
        assertThat(Verdict.NEEDS_REVIEW.json()).isEqualTo("needs-review");
        assertThat(TriageSeverity.HIGH.json()).isEqualTo("high");
    }
}
```

- [ ] **Step 5: Run test to verify it fails**

Run: `./gradlew :apps:ai-triage:test --tests '*TriageResultTest'`
Expected: FAIL — compilation error, classes do not exist.

- [ ] **Step 6: Create the records and enums**

`FindingRef.java`:

```java
package com.oversecured.sast.aitriage;

public record FindingRef(String ruleId, String file, int line) {
}
```

`TriageFlowStep.java`:

```java
package com.oversecured.sast.aitriage;

public record TriageFlowStep(String file, int line, String label) {
}
```

`TriageFinding.java`:

```java
package com.oversecured.sast.aitriage;

import java.util.List;

public record TriageFinding(
        String ruleId,
        String level,
        String message,
        String cwe,
        String owaspMobile,
        List<TriageFlowStep> flow,
        FindingRef ref) {
}
```

`Verdict.java`:

```java
package com.oversecured.sast.aitriage;

import com.fasterxml.jackson.annotation.JsonValue;

public enum Verdict {
    EXPLOITABLE("exploitable"),
    NEEDS_REVIEW("needs-review"),
    SAFE("safe");

    private final String json;

    Verdict(String json) {
        this.json = json;
    }

    @JsonValue
    public String json() {
        return json;
    }
}
```

`TriageSeverity.java`:

```java
package com.oversecured.sast.aitriage;

import com.fasterxml.jackson.annotation.JsonValue;

public enum TriageSeverity {
    CRITICAL, HIGH, MEDIUM, LOW, INFO;

    @JsonValue
    public String json() {
        return name().toLowerCase();
    }
}
```

`TriageItem.java`:

```java
package com.oversecured.sast.aitriage;

import java.util.List;

public record TriageItem(
        FindingRef ref,
        Verdict verdict,
        TriageSeverity severity,
        double confidence,
        String rationale,
        String fix,
        List<String> references) {
}
```

`TriageResult.java`:

```java
package com.oversecured.sast.aitriage;

import java.util.List;

public record TriageResult(String model, String generatedAt, String summary, List<TriageItem> items) {
}
```

- [ ] **Step 7: Run test to verify it passes**

Run: `./gradlew :apps:ai-triage:test --tests '*TriageResultTest'`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add settings.gradle build.gradle apps/ai-triage
git commit -m "feat(ai-triage): scaffold module + domain records"
```

---

### Task 2: SARIF parser

**Files:**
- Create: `apps/ai-triage/src/main/java/com/oversecured/sast/aitriage/SarifFindings.java`
- Test: `apps/ai-triage/src/test/java/com/oversecured/sast/aitriage/SarifFindingsTest.java`
- Test resource: `apps/ai-triage/src/test/resources/fixtures/report.sarif`

**Interfaces:**
- Consumes: `TriageFinding`, `TriageFlowStep`, `FindingRef` (Task 1).
- Produces: `class SarifFindings { List<TriageFinding> parse(Path sarif) throws IOException }`. `ref` = `FindingRef(ruleId, firstFlowStep.file, firstFlowStep.line)`; when a result has no `codeFlows`, `flow` is empty and `ref` falls back to the result's primary `locations[0]` physical location, or `("",  -1)` if absent. `cwe`/`owaspMobile` resolved from `driver.rules[]` (matched by `ruleId`) `properties.cwe` / `properties.owaspMobile`; `null` if absent.

- [ ] **Step 1: Create the SARIF fixture**

`apps/ai-triage/src/test/resources/fixtures/report.sarif` (the shape `SarifReportWriter` emits — sink in `locations`, full flow in `codeFlows`):

```json
{
  "version": "2.1.0",
  "runs": [
    {
      "tool": { "driver": { "name": "android-taint-sast", "rules": [
        { "id": "ANDROID_WEBVIEW_INTENT_LOADURL", "name": "webview-open-redirect",
          "properties": { "cwe": "CWE-601", "owaspMobile": "M1" } }
      ] } },
      "results": [
        {
          "ruleId": "ANDROID_WEBVIEW_INTENT_LOADURL",
          "level": "error",
          "message": { "text": "Untrusted deeplink data flows into WebView.loadUrl" },
          "locations": [
            { "physicalLocation": { "artifactLocation": { "uri": "WebViewActivity.java" },
              "region": { "startLine": 22 } } }
          ],
          "codeFlows": [ { "threadFlows": [ { "locations": [
            { "location": { "physicalLocation": { "artifactLocation": { "uri": "DeeplinkActivity.java" },
              "region": { "startLine": 47 } }, "message": { "text": "source: Uri.getQueryParameter(\"url\")" } } },
            { "location": { "physicalLocation": { "artifactLocation": { "uri": "WebViewActivity.java" },
              "region": { "startLine": 22 } }, "message": { "text": "sink: WebView.loadUrl(url)" } } }
          ] } ] } ]
        }
      ]
    }
  ]
}
```

- [ ] **Step 2: Write the failing test**

`SarifFindingsTest.java`:

```java
package com.oversecured.sast.aitriage;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class SarifFindingsTest {

    private Path fixture() throws Exception {
        return Path.of(getClass().getResource("/fixtures/report.sarif").toURI());
    }

    @Test
    void parsesResultWithFlowRuleMetadataAndRef() throws Exception {
        List<TriageFinding> findings = new SarifFindings().parse(fixture());

        assertThat(findings).hasSize(1);
        TriageFinding f = findings.get(0);
        assertThat(f.ruleId()).isEqualTo("ANDROID_WEBVIEW_INTENT_LOADURL");
        assertThat(f.level()).isEqualTo("error");
        assertThat(f.message()).contains("WebView.loadUrl");
        assertThat(f.cwe()).isEqualTo("CWE-601");
        assertThat(f.owaspMobile()).isEqualTo("M1");
        assertThat(f.flow()).hasSize(2);
        assertThat(f.flow().get(0)).isEqualTo(
                new TriageFlowStep("DeeplinkActivity.java", 47, "source: Uri.getQueryParameter(\"url\")"));
        assertThat(f.ref()).isEqualTo(new FindingRef("ANDROID_WEBVIEW_INTENT_LOADURL", "DeeplinkActivity.java", 47));
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `./gradlew :apps:ai-triage:test --tests '*SarifFindingsTest'`
Expected: FAIL — `SarifFindings` does not exist.

- [ ] **Step 4: Implement SarifFindings**

`SarifFindings.java`:

```java
package com.oversecured.sast.aitriage;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Parses the reporter's SARIF v2.1.0 document into triage findings. */
public final class SarifFindings {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public List<TriageFinding> parse(Path sarif) throws IOException {
        JsonNode root = MAPPER.readTree(Files.readString(sarif));
        List<TriageFinding> findings = new ArrayList<>();
        JsonNode runs = root.path("runs");
        for (JsonNode run : runs) {
            Map<String, JsonNode> rulesById = indexRules(run.path("tool").path("driver").path("rules"));
            for (JsonNode result : run.path("results")) {
                findings.add(toFinding(result, rulesById));
            }
        }
        return findings;
    }

    private Map<String, JsonNode> indexRules(JsonNode rules) {
        Map<String, JsonNode> byId = new HashMap<>();
        for (JsonNode rule : rules) {
            byId.put(rule.path("id").asText(""), rule);
        }
        return byId;
    }

    private TriageFinding toFinding(JsonNode result, Map<String, JsonNode> rulesById) {
        String ruleId = result.path("ruleId").asText("");
        String level = result.path("level").asText("");
        String message = result.path("message").path("text").asText("");

        List<TriageFlowStep> flow = new ArrayList<>();
        JsonNode tfLocations = result.path("codeFlows").path(0)
                .path("threadFlows").path(0).path("locations");
        for (JsonNode loc : tfLocations) {
            JsonNode location = loc.path("location");
            flow.add(new TriageFlowStep(
                    uri(location),
                    startLine(location),
                    location.path("message").path("text").asText("")));
        }

        FindingRef ref;
        if (!flow.isEmpty()) {
            ref = new FindingRef(ruleId, flow.get(0).file(), flow.get(0).line());
        } else {
            JsonNode primary = result.path("locations").path(0);
            ref = new FindingRef(ruleId, uri(primary), startLine(primary));
        }

        JsonNode rule = rulesById.get(ruleId);
        String cwe = rule == null ? null : textOrNull(rule.path("properties").path("cwe"));
        String owasp = rule == null ? null : textOrNull(rule.path("properties").path("owaspMobile"));

        return new TriageFinding(ruleId, level, message, cwe, owasp, flow, ref);
    }

    private String uri(JsonNode location) {
        return location.path("physicalLocation").path("artifactLocation").path("uri").asText("");
    }

    private int startLine(JsonNode location) {
        return location.path("physicalLocation").path("region").path("startLine").asInt(-1);
    }

    private String textOrNull(JsonNode node) {
        return node.isMissingNode() || node.isNull() ? null : node.asText();
    }
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `./gradlew :apps:ai-triage:test --tests '*SarifFindingsTest'`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add apps/ai-triage/src
git commit -m "feat(ai-triage): parse SARIF into triage findings"
```

---

### Task 3: Path-jailed source tools

**Files:**
- Create: `apps/ai-triage/src/main/java/com/oversecured/sast/aitriage/SourceTools.java`
- Test: `apps/ai-triage/src/test/java/com/oversecured/sast/aitriage/SourceToolsTest.java`

**Interfaces:**
- Produces: `class SourceTools` constructed with `SourceTools(Path sourcesRoot)`. Methods (each `@dev.langchain4j.agent.tool.Tool`):
  - `String readFile(String relpath, Integer start, Integer end)` — 1-based inclusive line range; `null` start/end mean whole file; output lines prefixed `"<n>\t"`. Out-of-jail path → returns the literal string `"ERROR: path escapes sources root"`. Missing file → `"ERROR: file not found: <relpath>"`.
  - `String listDir(String relpath)` — newline-joined names; same jail/Error contract.
  - `String searchCode(String query)` — up to 50 `"<relfile>:<line>: <text>"` matches across `*.java`; jailed to root.

- [ ] **Step 1: Write the failing test**

`SourceToolsTest.java`:

```java
package com.oversecured.sast.aitriage;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SourceToolsTest {

    @Test
    void readFileReturnsNumberedSlice(@TempDir Path root) throws Exception {
        Files.writeString(root.resolve("A.java"), "line1\nline2\nline3\nline4\n");
        SourceTools tools = new SourceTools(root);

        String out = tools.readFile("A.java", 2, 3);

        assertThat(out).isEqualTo("2\tline2\n3\tline3");
    }

    @Test
    void readFileRejectsPathEscape(@TempDir Path root) throws Exception {
        Files.writeString(root.resolve("A.java"), "x");
        SourceTools tools = new SourceTools(root);

        assertThat(tools.readFile("../secret.txt", null, null))
                .isEqualTo("ERROR: path escapes sources root");
        assertThat(tools.readFile("/etc/passwd", null, null))
                .isEqualTo("ERROR: path escapes sources root");
    }

    @Test
    void readFileReportsMissing(@TempDir Path root) {
        SourceTools tools = new SourceTools(root);
        assertThat(tools.readFile("Nope.java", null, null))
                .isEqualTo("ERROR: file not found: Nope.java");
    }

    @Test
    void searchCodeFindsMatches(@TempDir Path root) throws Exception {
        Files.createDirectories(root.resolve("p"));
        Files.writeString(root.resolve("p/B.java"), "class B {\n  void loadUrl() {}\n}\n");
        SourceTools tools = new SourceTools(root);

        assertThat(tools.searchCode("loadUrl")).contains("p/B.java:2:");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :apps:ai-triage:test --tests '*SourceToolsTest'`
Expected: FAIL — `SourceTools` does not exist.

- [ ] **Step 3: Implement SourceTools**

`SourceTools.java`:

```java
package com.oversecured.sast.aitriage;

import dev.langchain4j.agent.tool.P;
import dev.langchain4j.agent.tool.Tool;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/** Filesystem tools exposed to the agent, jailed to the decompiled sources root. */
public final class SourceTools {

    private static final int MAX_MATCHES = 50;

    private final Path root;

    public SourceTools(Path sourcesRoot) {
        this.root = sourcesRoot.toAbsolutePath().normalize();
    }

    @Tool("Read a source file (paths relative to the sources root). "
            + "Optional 1-based inclusive start/end line range.")
    public String readFile(
            @P("relative file path") String relpath,
            @P(value = "start line, 1-based, inclusive; null for start of file", required = false) Integer start,
            @P(value = "end line, 1-based, inclusive; null for end of file", required = false) Integer end) {
        Path resolved = jail(relpath);
        if (resolved == null) {
            return "ERROR: path escapes sources root";
        }
        if (!Files.isRegularFile(resolved)) {
            return "ERROR: file not found: " + relpath;
        }
        List<String> lines = readLines(resolved);
        int from = start == null ? 1 : Math.max(1, start);
        int to = end == null ? lines.size() : Math.min(lines.size(), end);
        StringBuilder sb = new StringBuilder();
        for (int i = from; i <= to; i++) {
            if (sb.length() > 0) {
                sb.append("\n");
            }
            sb.append(i).append("\t").append(lines.get(i - 1));
        }
        return sb.toString();
    }

    @Tool("List the entries of a directory relative to the sources root.")
    public String listDir(@P("relative directory path") String relpath) {
        Path resolved = jail(relpath);
        if (resolved == null) {
            return "ERROR: path escapes sources root";
        }
        if (!Files.isDirectory(resolved)) {
            return "ERROR: directory not found: " + relpath;
        }
        try (Stream<Path> entries = Files.list(resolved)) {
            return entries.map(p -> p.getFileName().toString()).sorted().reduce((a, b) -> a + "\n" + b).orElse("");
        } catch (IOException e) {
            return "ERROR: " + e.getMessage();
        }
    }

    @Tool("Search all .java files under the sources root for a substring. "
            + "Returns up to 50 'file:line: text' matches.")
    public String searchCode(@P("substring to search for") String query) {
        List<String> matches = new ArrayList<>();
        try (Stream<Path> files = Files.walk(root)) {
            files.filter(Files::isRegularFile)
                    .filter(p -> p.toString().endsWith(".java"))
                    .forEach(p -> collectMatches(p, query, matches));
        } catch (IOException e) {
            return "ERROR: " + e.getMessage();
        }
        return String.join("\n", matches);
    }

    private void collectMatches(Path file, String query, List<String> matches) {
        if (matches.size() >= MAX_MATCHES) {
            return;
        }
        List<String> lines = readLines(file);
        String rel = root.relativize(file).toString();
        for (int i = 0; i < lines.size() && matches.size() < MAX_MATCHES; i++) {
            if (lines.get(i).contains(query)) {
                matches.add(rel + ":" + (i + 1) + ": " + lines.get(i).trim());
            }
        }
    }

    private Path jail(String relpath) {
        if (relpath == null) {
            return null;
        }
        Path resolved = root.resolve(relpath).normalize();
        return resolved.startsWith(root) ? resolved : null;
    }

    private List<String> readLines(Path file) {
        try {
            return Files.readAllLines(file);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :apps:ai-triage:test --tests '*SourceToolsTest'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add apps/ai-triage/src
git commit -m "feat(ai-triage): path-jailed source tools for the agent"
```

---

### Task 4: Prompt builder

**Files:**
- Create: `apps/ai-triage/src/main/java/com/oversecured/sast/aitriage/TriagePrompt.java`
- Test: `apps/ai-triage/src/test/java/com/oversecured/sast/aitriage/TriagePromptTest.java`

**Interfaces:**
- Consumes: `TriageFinding`, `TriageFlowStep` (Tasks 1-2).
- Produces: `final class TriagePrompt` with `public static final String SYSTEM` (compile-time constant — usable in `@SystemMessage`) and `static String renderFindings(List<TriageFinding> findings)`.

- [ ] **Step 1: Write the failing test**

`TriagePromptTest.java`:

```java
package com.oversecured.sast.aitriage;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class TriagePromptTest {

    @Test
    void systemPromptNamesVerdicts() {
        assertThat(TriagePrompt.SYSTEM)
                .contains("exploitable")
                .contains("needs-review")
                .contains("safe");
    }

    @Test
    void renderFindingsListsRefsAndFlow() {
        TriageFinding f = new TriageFinding(
                "RULE_X", "error", "msg", "CWE-601", "M1",
                List.of(new TriageFlowStep("A.java", 47, "source: x"),
                        new TriageFlowStep("B.java", 22, "sink: y")),
                new FindingRef("RULE_X", "A.java", 47));

        String text = TriagePrompt.renderFindings(List.of(f));

        assertThat(text).contains("Triage these 1 findings");
        assertThat(text).contains("[1] ruleId: RULE_X");
        assertThat(text).contains("A.java:47");
        assertThat(text).contains("B.java:22");
        assertThat(text).contains("ref: {ruleId: RULE_X, file: A.java, line: 47}");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :apps:ai-triage:test --tests '*TriagePromptTest'`
Expected: FAIL — `TriagePrompt` does not exist.

- [ ] **Step 3: Implement TriagePrompt**

`TriagePrompt.java` (copy `SYSTEM` verbatim from the spec's Agent prompt section, `docs/superpowers/specs/2026-06-28-ai-triage-step-design.md`):

```java
package com.oversecured.sast.aitriage;

import java.util.List;

public final class TriagePrompt {

    private TriagePrompt() {
    }

    public static final String SYSTEM = """
            You are a senior Android application security analyst performing triage on
            static-analysis (SAST) findings for a decompiled APK.

            You are given a list of findings from a taint/misconfig engine. Each finding
            has a rule, a message, and a data-flow path of file:line steps from an
            untrusted SOURCE to a dangerous SINK. The source code referenced by those
            paths is available to you through tools - it is DECOMPILED, so expect synthetic
            names, missing comments, and occasional artifacts.

            Your job, for EVERY finding:
              1. Read the actual source at the flow's source, sink, and intermediate steps.
                 Do not judge from the message alone - verify against the code.
              2. Decide a verdict:
                   - "exploitable"   : a realistic attacker-controlled path reaches the sink
                                       with no effective sanitization.
                   - "needs-review"  : plausible but depends on context you cannot confirm
                                       (caller, runtime config, reachability).
                   - "safe"          : false positive - sanitized, unreachable, not
                                       attacker-controlled, or dead code. Justify why.
              3. Assign severity (critical|high|medium|low|info) based on real impact and
                 attacker effort, NOT just the engine's default level.
              4. Give a confidence in [0,1] for your verdict.
              5. Write a concrete fix: the specific code-level change (API, validation,
                 flag), not generic advice. Reference the file:line you would change.

            Correlate findings that share a sink or flow through the same code - call this
            out in the rationale rather than repeating analysis.

            Rules of engagement:
              - Only use the provided tools to read files. Paths are relative to the
                sources root. Never assume file contents.
              - If a referenced file or line cannot be found, say so and lower confidence;
                do not fabricate code.
              - Be specific and terse. No boilerplate security lectures.
              - Cite CWE and OWASP-Mobile ids where they apply.

            Return one item per input finding, each keyed by its ref {ruleId, file, line}.
            Do not drop or merge findings; every input gets exactly one verdict. The verdict
            must be one of exploitable, needs-review, safe. The severity must be one of
            critical, high, medium, low, info.
            """;

    public static String renderFindings(List<TriageFinding> findings) {
        StringBuilder sb = new StringBuilder();
        sb.append("Triage these ").append(findings.size())
                .append(" findings. Read the source before judging each one.\n");
        int i = 1;
        for (TriageFinding f : findings) {
            sb.append("\n[").append(i++).append("] ruleId: ").append(f.ruleId())
                    .append("  (level: ").append(f.level())
                    .append(", CWE: ").append(f.cwe())
                    .append(", OWASP: ").append(f.owaspMobile()).append(")\n");
            sb.append("    message: ").append(f.message()).append("\n");
            sb.append("    flow:\n");
            for (TriageFlowStep step : f.flow()) {
                sb.append("      - ").append(step.file()).append(":").append(step.line())
                        .append("  ").append(step.label()).append("\n");
            }
            FindingRef ref = f.ref();
            sb.append("    ref: {ruleId: ").append(ref.ruleId())
                    .append(", file: ").append(ref.file())
                    .append(", line: ").append(ref.line()).append("}\n");
        }
        return sb.toString();
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :apps:ai-triage:test --tests '*TriagePromptTest'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add apps/ai-triage/src
git commit -m "feat(ai-triage): system prompt + findings message renderer"
```

---

### Task 5: JSON + Markdown rendering

**Files:**
- Create: `apps/ai-triage/src/main/java/com/oversecured/sast/aitriage/TriageJson.java`
- Create: `apps/ai-triage/src/main/java/com/oversecured/sast/aitriage/MarkdownRenderer.java`
- Test: `apps/ai-triage/src/test/java/com/oversecured/sast/aitriage/TriageRenderingTest.java`

**Interfaces:**
- Consumes: `TriageResult`, `TriageItem`, `Verdict`, `TriageSeverity`, `FindingRef` (Task 1).
- Produces:
  - `final class TriageJson` — `static String write(TriageResult)` (pretty JSON, lowercase enums) and `static TriageResult read(String)`.
  - `final class MarkdownRenderer` — `static String render(TriageResult)`.

- [ ] **Step 1: Write the failing test**

`TriageRenderingTest.java`:

```java
package com.oversecured.sast.aitriage;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class TriageRenderingTest {

    private TriageResult sample() {
        return new TriageResult("openrouter/x", "2026-06-28T00:00:00Z", "1 exploitable.",
                List.of(new TriageItem(
                        new FindingRef("RULE_X", "A.java", 47),
                        Verdict.EXPLOITABLE, TriageSeverity.HIGH, 0.85,
                        "untrusted url reaches loadUrl", "use allowlist", List.of("CWE-601"))));
    }

    @Test
    void jsonRoundTripsAndLowercasesEnums() {
        String json = TriageJson.write(sample());

        assertThat(json).contains("\"verdict\" : \"exploitable\"");
        assertThat(json).contains("\"severity\" : \"high\"");
        TriageResult back = TriageJson.read(json);
        assertThat(back.items().get(0).verdict()).isEqualTo(Verdict.EXPLOITABLE);
        assertThat(back.items().get(0).ref().line()).isEqualTo(47);
    }

    @Test
    void markdownHasSummaryAndPerFindingSection() {
        String md = MarkdownRenderer.render(sample());

        assertThat(md).contains("# AI Triage");
        assertThat(md).contains("1 exploitable.");
        assertThat(md).contains("RULE_X");
        assertThat(md).contains("A.java:47");
        assertThat(md).contains("exploitable");
        assertThat(md).contains("use allowlist");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :apps:ai-triage:test --tests '*TriageRenderingTest'`
Expected: FAIL — classes do not exist.

- [ ] **Step 3: Implement TriageJson**

`TriageJson.java`:

```java
package com.oversecured.sast.aitriage;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public final class TriageJson {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private TriageJson() {
    }

    public static String write(TriageResult result) {
        try {
            return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(result);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("failed to serialize triage result", e);
        }
    }

    public static TriageResult read(String json) {
        try {
            return MAPPER.readValue(json, TriageResult.class);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("failed to deserialize triage result", e);
        }
    }
}
```

Note: deserialization of the `@JsonValue` enums needs no extra code — Jackson maps the string back via the single-arg path for `TriageSeverity`. For `Verdict` (custom label), add a `@com.fasterxml.jackson.annotation.JsonCreator` factory. Update `Verdict.java` from Task 1 by appending:

```java
    @com.fasterxml.jackson.annotation.JsonCreator
    public static Verdict fromJson(String value) {
        for (Verdict v : values()) {
            if (v.json.equals(value)) {
                return v;
            }
        }
        throw new IllegalArgumentException("unknown verdict: " + value);
    }
```

And `TriageSeverity.java` by appending:

```java
    @com.fasterxml.jackson.annotation.JsonCreator
    public static TriageSeverity fromJson(String value) {
        return valueOf(value.toUpperCase());
    }
```

- [ ] **Step 4: Implement MarkdownRenderer**

`MarkdownRenderer.java`:

```java
package com.oversecured.sast.aitriage;

public final class MarkdownRenderer {

    private MarkdownRenderer() {
    }

    public static String render(TriageResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append("# AI Triage\n\n");
        sb.append("_Model: ").append(result.model())
                .append(" — generated ").append(result.generatedAt()).append("_\n\n");
        sb.append(result.summary()).append("\n");
        for (TriageItem item : result.items()) {
            FindingRef ref = item.ref();
            sb.append("\n## ").append(ref.ruleId())
                    .append(" (").append(ref.file()).append(":").append(ref.line()).append(")\n\n");
            sb.append("- **Verdict:** ").append(item.verdict().json()).append("\n");
            sb.append("- **Severity:** ").append(item.severity().json()).append("\n");
            sb.append("- **Confidence:** ").append(item.confidence()).append("\n");
            sb.append("- **Rationale:** ").append(item.rationale()).append("\n");
            sb.append("- **Fix:** ").append(item.fix()).append("\n");
            if (item.references() != null && !item.references().isEmpty()) {
                sb.append("- **References:** ").append(String.join(", ", item.references())).append("\n");
            }
        }
        return sb.toString();
    }
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `./gradlew :apps:ai-triage:test --tests '*TriageRenderingTest'`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add apps/ai-triage/src
git commit -m "feat(ai-triage): JSON + Markdown rendering of triage result"
```

---

### Task 6: Analyzer orchestration + fail-soft (fake engine)

**Files:**
- Create: `apps/ai-triage/src/main/java/com/oversecured/sast/aitriage/TriageEngine.java`
- Create: `.../TriageEngineFactory.java`
- Create: `.../AiTriageAnalyzer.java`
- Test: `apps/ai-triage/src/test/java/com/oversecured/sast/aitriage/AiTriageAnalyzerTest.java`

**Interfaces:**
- Consumes: `SarifFindings`, `TriageResult`, `TriageJson`, `MarkdownRenderer` (Tasks 2,5).
- Produces:
  - `interface TriageEngine { TriageResult triage(List<TriageFinding> findings); String modelName(); }`
  - `interface TriageEngineFactory { TriageEngine create(Path sourcesDir); }` (returns `null` when unavailable, e.g. no API key)
  - `class AiTriageAnalyzer` with:
    - `public AiTriageAnalyzer()` — production: factory wired to `LangChainTriageEngine` (Task 7).
    - `AiTriageAnalyzer(TriageEngineFactory factory)` — injected (tests/production).
    - `public void run(Path sarif, Path sourcesDir, Path outJson, Path outMd)` — never throws. Writes both files. On no engine, empty findings, or any error → empty sidecar (`items: []`, summary explains why).

- [ ] **Step 1: Write the failing test**

`AiTriageAnalyzerTest.java`:

```java
package com.oversecured.sast.aitriage;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AiTriageAnalyzerTest {

    private Path sarifFixture(Path dir) throws Exception {
        Path src = Path.of(getClass().getResource("/fixtures/report.sarif").toURI());
        Path dest = dir.resolve("report.sarif");
        Files.copy(src, dest);
        return dest;
    }

    @Test
    void writesSidecarFromEngineResult(@TempDir Path dir) throws Exception {
        Path sarif = sarifFixture(dir);
        TriageResult canned = new TriageResult("fake-model", "2026-06-28T00:00:00Z", "done",
                List.of(new TriageItem(new FindingRef("ANDROID_WEBVIEW_INTENT_LOADURL", "DeeplinkActivity.java", 47),
                        Verdict.EXPLOITABLE, TriageSeverity.HIGH, 0.9, "r", "f", List.of("CWE-601"))));
        AiTriageAnalyzer analyzer = new AiTriageAnalyzer(sources -> new TriageEngine() {
            public TriageResult triage(List<TriageFinding> f) {
                return canned;
            }

            public String modelName() {
                return "fake-model";
            }
        });

        Path outJson = dir.resolve("ai-triage.json");
        Path outMd = dir.resolve("ai-triage.md");
        analyzer.run(sarif, dir, outJson, outMd);

        TriageResult written = TriageJson.read(Files.readString(outJson));
        assertThat(written.items()).hasSize(1);
        assertThat(written.items().get(0).verdict()).isEqualTo(Verdict.EXPLOITABLE);
        assertThat(Files.readString(outMd)).contains("ANDROID_WEBVIEW_INTENT_LOADURL");
    }

    @Test
    void writesEmptySidecarWhenNoEngine(@TempDir Path dir) throws Exception {
        Path sarif = sarifFixture(dir);
        AiTriageAnalyzer analyzer = new AiTriageAnalyzer(sources -> null);

        Path outJson = dir.resolve("ai-triage.json");
        Path outMd = dir.resolve("ai-triage.md");
        analyzer.run(sarif, dir, outJson, outMd);

        TriageResult written = TriageJson.read(Files.readString(outJson));
        assertThat(written.items()).isEmpty();
        assertThat(written.summary()).contains("skipped");
        assertThat(Files.exists(outMd)).isTrue();
    }

    @Test
    void writesEmptySidecarWhenEngineThrows(@TempDir Path dir) throws Exception {
        Path sarif = sarifFixture(dir);
        AiTriageAnalyzer analyzer = new AiTriageAnalyzer(sources -> new TriageEngine() {
            public TriageResult triage(List<TriageFinding> f) {
                throw new RuntimeException("API down");
            }

            public String modelName() {
                return "boom";
            }
        });

        Path outJson = dir.resolve("ai-triage.json");
        Path outMd = dir.resolve("ai-triage.md");
        analyzer.run(sarif, dir, outJson, outMd); // must not throw

        assertThat(TriageJson.read(Files.readString(outJson)).items()).isEmpty();
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :apps:ai-triage:test --tests '*AiTriageAnalyzerTest'`
Expected: FAIL — classes do not exist.

- [ ] **Step 3: Implement the interfaces**

`TriageEngine.java`:

```java
package com.oversecured.sast.aitriage;

import java.util.List;

public interface TriageEngine {
    TriageResult triage(List<TriageFinding> findings);

    String modelName();
}
```

`TriageEngineFactory.java`:

```java
package com.oversecured.sast.aitriage;

import java.nio.file.Path;

@FunctionalInterface
public interface TriageEngineFactory {
    /** Returns an engine for this sources root, or null if unavailable (e.g. no API key). */
    TriageEngine create(Path sourcesDir);
}
```

- [ ] **Step 4: Implement AiTriageAnalyzer**

`AiTriageAnalyzer.java`:

```java
package com.oversecured.sast.aitriage;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

/** Always-on, fail-soft AI triage step. Never throws; always writes both sidecar files. */
public final class AiTriageAnalyzer {

    private final TriageEngineFactory factory;

    public AiTriageAnalyzer() {
        this(defaultFactory());
    }

    public AiTriageAnalyzer(TriageEngineFactory factory) {
        this.factory = factory;
    }

    public void run(Path sarif, Path sourcesDir, Path outJson, Path outMd) {
        TriageResult result;
        try {
            List<TriageFinding> findings = new SarifFindings().parse(sarif);
            TriageEngine engine = factory.create(sourcesDir);
            if (engine == null) {
                result = empty("AI triage skipped: no engine available (set OPENROUTER_API_KEY).");
            } else if (findings.isEmpty()) {
                result = empty("AI triage skipped: no findings to analyze.");
            } else {
                result = engine.triage(findings);
            }
        } catch (Exception e) {
            result = empty("AI triage skipped: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        writeSoft(outJson, TriageJson.write(result));
        writeSoft(outMd, MarkdownRenderer.render(result));
    }

    private TriageResult empty(String summary) {
        return new TriageResult(null, Instant.now().toString(), summary, List.of());
    }

    private void writeSoft(Path path, String content) {
        try {
            if (path.getParent() != null) {
                Files.createDirectories(path.getParent());
            }
            Files.writeString(path, content);
        } catch (IOException e) {
            // Last-resort: cannot write the sidecar. Swallow — the step must not break the pipeline.
            System.err.println("ai-triage: failed to write " + path + ": " + e.getMessage());
        }
    }

    private static TriageEngineFactory defaultFactory() {
        String model = System.getenv().getOrDefault("OPENROUTER_MODEL", "anthropic/claude-3.5-sonnet");
        return sourcesDir -> LangChainTriageEngine.create(
                System.getenv("OPENROUTER_API_KEY"),
                "https://openrouter.ai/api/v1",
                model,
                sourcesDir);
    }
}
```

Note: `defaultFactory` references `LangChainTriageEngine.create` (Task 7). This task will not compile until Task 7 adds that class — implement Task 7 immediately after, OR temporarily stub `defaultFactory` to `sourcesDir -> null` and restore it in Task 7. The injected-factory tests above do not exercise `defaultFactory`, so they pass once Task 7 compiles. **Recommended:** do Steps 1-3 here, then jump to Task 7, then run this task's tests.

- [ ] **Step 5: Run test to verify it passes** (after Task 7 compiles)

Run: `./gradlew :apps:ai-triage:test --tests '*AiTriageAnalyzerTest'`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add apps/ai-triage/src
git commit -m "feat(ai-triage): fail-soft analyzer orchestration"
```

---

### Task 7: LangChain4j production engine

**Files:**
- Create: `apps/ai-triage/src/main/java/com/oversecured/sast/aitriage/LangChainTriageEngine.java`
- Test: `apps/ai-triage/src/test/java/com/oversecured/sast/aitriage/LangChainTriageEngineTest.java`

**Interfaces:**
- Consumes: `TriageEngine`, `SourceTools`, `TriagePrompt`, `TriageResult`, `TriageItem` (Tasks 1-6).
- Produces: `final class LangChainTriageEngine implements TriageEngine` with `public static TriageEngine create(String apiKey, String baseUrl, String model, Path sourcesDir)` — returns `null` when `apiKey` is null/blank; otherwise builds the model + `AiServices` (no network call until `triage` runs). `triage(...)` stamps `model` + `generatedAt` onto the model's structured output.

- [ ] **Step 1: Write the failing test (offline only)**

`LangChainTriageEngineTest.java`:

```java
package com.oversecured.sast.aitriage;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class LangChainTriageEngineTest {

    @Test
    void createReturnsNullWithoutApiKey(@TempDir Path dir) {
        assertThat(LangChainTriageEngine.create(null, "https://x", "m", dir)).isNull();
        assertThat(LangChainTriageEngine.create("  ", "https://x", "m", dir)).isNull();
    }

    @Test
    void createBuildsEngineWithApiKeyWithoutCallingNetwork(@TempDir Path dir) {
        TriageEngine engine = LangChainTriageEngine.create("sk-test", "https://x", "test-model", dir);
        assertThat(engine).isNotNull();
        assertThat(engine.modelName()).isEqualTo("test-model");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :apps:ai-triage:test --tests '*LangChainTriageEngineTest'`
Expected: FAIL — `LangChainTriageEngine` does not exist.

- [ ] **Step 3: Implement LangChainTriageEngine**

`LangChainTriageEngine.java`:

```java
package com.oversecured.sast.aitriage;

import dev.langchain4j.model.chat.ChatModel;
import dev.langchain4j.model.openai.OpenAiChatModel;
import dev.langchain4j.service.AiServices;
import dev.langchain4j.service.SystemMessage;
import dev.langchain4j.service.UserMessage;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

/** Production triage engine backed by LangChain4j over an OpenAI-compatible (OpenRouter) model. */
public final class LangChainTriageEngine implements TriageEngine {

    /** Structured-output AI service. LangChain4j derives a JSON schema from TriageResult. */
    interface TriageAiService {
        @SystemMessage(TriagePrompt.SYSTEM)
        TriageResult triage(@UserMessage String findings);
    }

    private final TriageAiService service;
    private final String model;

    private LangChainTriageEngine(TriageAiService service, String model) {
        this.service = service;
        this.model = model;
    }

    public static TriageEngine create(String apiKey, String baseUrl, String model, Path sourcesDir) {
        if (apiKey == null || apiKey.isBlank()) {
            return null;
        }
        ChatModel chatModel = OpenAiChatModel.builder()
                .baseUrl(baseUrl)
                .apiKey(apiKey)
                .modelName(model)
                .build();
        TriageAiService service = AiServices.builder(TriageAiService.class)
                .chatModel(chatModel)
                .tools(new SourceTools(sourcesDir))
                .build();
        return new LangChainTriageEngine(service, model);
    }

    @Override
    public TriageResult triage(List<TriageFinding> findings) {
        TriageResult raw = service.triage(TriagePrompt.renderFindings(findings));
        return new TriageResult(model, Instant.now().toString(), raw.summary(), raw.items());
    }

    @Override
    public String modelName() {
        return model;
    }
}
```

Note on API names: this targets LangChain4j 1.1.0 — `dev.langchain4j.model.chat.ChatModel`, `OpenAiChatModel.builder()`, `AiServices.builder(...).chatModel(...)`, `@SystemMessage`, `@UserMessage`. If the resolved jar exposes `chatLanguageModel(...)` instead of `chatModel(...)`, use that builder method — verify against the downloaded dependency, do not guess past a compile error.

- [ ] **Step 4: Run tests to verify they pass**

Run: `./gradlew :apps:ai-triage:test --tests '*LangChainTriageEngineTest'`
Expected: PASS.

- [ ] **Step 5: Restore AiTriageAnalyzer.defaultFactory (if stubbed in Task 6)**

Ensure `AiTriageAnalyzer.defaultFactory` calls `LangChainTriageEngine.create(...)` as written in Task 6 Step 4, then run the full module test suite:

Run: `./gradlew :apps:ai-triage:test`
Expected: PASS (all of Tasks 1-7).

- [ ] **Step 6: Commit**

```bash
git add apps/ai-triage/src
git commit -m "feat(ai-triage): LangChain4j OpenRouter engine + structured output"
```

---

### Task 8: Orchestrator activity

**Files:**
- Create: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/activities/AiTriageActivityInput.java`
- Modify: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/activities/PipelineActivities.java`
- Modify: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/activities/PipelineActivitiesImpl.java`
- Modify: `orchestrator/build.gradle`
- Test: `orchestrator/src/test/java/com/oversecured/sast/orchestrator/PipelineActivitiesImplTest.java`

**Interfaces:**
- Consumes: `StepResult` (`status` package), `ArtifactRef`, `AiTriageAnalyzer` (Task 6).
- Produces:
  - `record AiTriageActivityInput(String sarifKey, String sourcesDirKey, String outJsonKey, String outMdKey)`
  - `PipelineActivities.aiTriage(AiTriageActivityInput) : StepResult` (nodeId `"ai-triage"`, artifacts `ArtifactRef("ai-triage-json", outJsonKey)` and `ArtifactRef("ai-triage-md", outMdKey)`).
  - `StepApis.aiTriage(Path sarif, Path sourcesDir, Path outJson, Path outMd)`.

- [ ] **Step 1: Add orchestrator dependency on the module**

In `orchestrator/build.gradle`, in `dependencies`, after `implementation project(':apps:reporter')`:

```gradle
    implementation project(':apps:ai-triage')
```

- [ ] **Step 2: Write the failing test**

Add to `PipelineActivitiesImplTest.java`. In the `RecordingStepApis` inner class, add the new `StepApis` method:

```java
        @Override
        public void aiTriage(Path sarif, Path sourcesDir, Path outJson, Path outMd) {
            calls.add("aitriage:" + sarif + "->" + outJson + ":" + outMd);
            try {
                Files.createDirectories(outJson.getParent());
                Files.writeString(outJson, "{\"items\":[]}");
                Files.writeString(outMd, "# AI Triage\n");
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
```

Add a new `@Test` method:

```java
    @Test
    void aiTriageResolvesKeysAndReturnsArtifacts(@TempDir Path root) {
        RecordingStepApis apis = new RecordingStepApis();
        PipelineActivitiesImpl activities = PipelineActivitiesImpl.forTesting(root, apis);

        StepResult result = activities.aiTriage(new com.oversecured.sast.orchestrator.activities.AiTriageActivityInput(
                "runs/r1/report.sarif",
                "runs/r1/sources",
                "runs/r1/ai-triage.json",
                "runs/r1/ai-triage.md"));

        assertThat(result.nodeId()).isEqualTo("ai-triage");
        assertThat(result.artifacts()).containsExactly(
                new ArtifactRef("ai-triage-json", "runs/r1/ai-triage.json"),
                new ArtifactRef("ai-triage-md", "runs/r1/ai-triage.md"));
        assertThat(apis.calls).containsExactly(
                "aitriage:" + root.resolve("runs/r1/report.sarif").toAbsolutePath().normalize()
                        + "->" + root.resolve("runs/r1/ai-triage.json").toAbsolutePath().normalize()
                        + ":" + root.resolve("runs/r1/ai-triage.md").toAbsolutePath().normalize());
    }
```

- [ ] **Step 3: Run test to verify it fails**

Run: `./gradlew :orchestrator:test --tests '*PipelineActivitiesImplTest'`
Expected: FAIL — `AiTriageActivityInput` / `aiTriage` do not exist (compile error).

- [ ] **Step 4: Create AiTriageActivityInput**

`AiTriageActivityInput.java`:

```java
package com.oversecured.sast.orchestrator.activities;

public record AiTriageActivityInput(String sarifKey, String sourcesDirKey, String outJsonKey, String outMdKey) {
}
```

- [ ] **Step 5: Add the interface method**

In `PipelineActivities.java`, after the `report` method:

```java
    @ActivityMethod
    StepResult aiTriage(AiTriageActivityInput input);
```

- [ ] **Step 6: Implement the activity**

In `PipelineActivitiesImpl.java`, add the method (alongside `report`). It does NOT use `withPipelineFailureBoundary` — the analyzer is fail-soft and never throws:

```java
    @Override
    public StepResult aiTriage(AiTriageActivityInput input) {
        Path sarif = paths.resolveArtifactKey(input.sarifKey());
        Path sourcesDir = paths.resolveArtifactKey(input.sourcesDirKey());
        Path outJson = paths.resolveArtifactKey(input.outJsonKey());
        Path outMd = paths.resolveArtifactKey(input.outMdKey());
        apis.aiTriage(sarif, sourcesDir, outJson, outMd);
        return StepResult.completed(
                "ai-triage",
                "Generated AI triage analysis.",
                Map.of(
                        "aiTriageJsonWritten", Files.exists(outJson),
                        "aiTriageMdWritten", Files.exists(outMd)),
                List.of(
                        new ArtifactRef("ai-triage-json", input.outJsonKey()),
                        new ArtifactRef("ai-triage-md", input.outMdKey())),
                List.of(),
                0,
                Map.of());
    }
```

Add to the `StepApis` interface:

```java
        void aiTriage(Path sarif, Path sourcesDir, Path outJson, Path outMd);
```

Add to `ProductionStepApis`:

```java
        @Override
        public void aiTriage(Path sarif, Path sourcesDir, Path outJson, Path outMd) {
            new com.oversecured.sast.aitriage.AiTriageAnalyzer().run(sarif, sourcesDir, outJson, outMd);
        }
```

- [ ] **Step 7: Run test to verify it passes**

Run: `./gradlew :orchestrator:test --tests '*PipelineActivitiesImplTest'`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/build.gradle orchestrator/src
git commit -m "feat(ai-triage): orchestrator aiTriage activity"
```

---

### Task 9: Workflow + plan wiring

**Files:**
- Modify: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/AnalysisPlan.java` (`ReportConfig`)
- Modify: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/AnalysisResult.java`
- Modify: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/cli/StartAnalysisCommand.java`
- Modify: `orchestrator/src/main/java/com/oversecured/sast/orchestrator/workflow/AnalyzeApkWorkflowImpl.java`
- Test: `orchestrator/src/test/java/com/oversecured/sast/orchestrator/AnalyzeApkWorkflowTest.java`
- Test: `orchestrator/src/test/java/com/oversecured/sast/orchestrator/StartAnalysisCommandTest.java`

**Interfaces:**
- Consumes: `AiTriageActivityInput`, `PipelineActivities.aiTriage` (Task 8).
- Produces:
  - `ReportConfig(String htmlKey, String sarifKey, String aiTriageJsonKey, String aiTriageMdKey)`; `forRules` sets `aiTriageJsonKey = root + "/ai-triage.json"`, `aiTriageMdKey = root + "/ai-triage.md"`.
  - `AnalysisResult(String htmlReportKey, String sarifReportKey, String aiTriageJsonKey, String aiTriageMdKey)`.
  - Workflow node `"ai-triage"` runs after `report`; status node def label `"AI Triage"`, lane `"report"`.

- [ ] **Step 1: Update the workflow test (DAG order + result keys)**

In `AnalyzeApkWorkflowTest.java`, update the `RecordingActivities` to implement the new activity (find the inner class implementing `PipelineActivities`). Add a field + method; mirror the existing `report` recording style:

```java
        @Override
        public StepResult aiTriage(com.oversecured.sast.orchestrator.activities.AiTriageActivityInput input) {
            calls.add("aitriage:" + input.outJsonKey() + ":" + input.outMdKey());
            return StepResult.completed("ai-triage", "ai triage",
                    Map.of(),
                    List.of(),
                    List.of(), 0, Map.of());
        }
```

Update the first test's assertions. Replace the `result` equality assertion (around line 53) with:

```java
        assertThat(result).isEqualTo(new AnalysisResult(
                "runs/run-1/report.html",
                "runs/run-1/report.sarif",
                "runs/run-1/ai-triage.json",
                "runs/run-1/ai-triage.md"));
```

Replace the `endsWith("report:...")` assertion with an assertion that ai-triage is last and runs after report:

```java
        assertThat(activities.calls).containsSubsequence(
                "report:runs/run-1/report.html:runs/run-1/report.sarif",
                "aitriage:runs/run-1/ai-triage.json:runs/run-1/ai-triage.md");
        assertThat(activities.calls).endsWith("aitriage:runs/run-1/ai-triage.json:runs/run-1/ai-triage.md");
```

> If `RecordingActivities.report` does not currently record a `"report:..."` string in `calls`, add that recording line to its `report` override to make the subsequence assertion meaningful — match the format used in the existing `endsWith` assertion.

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :orchestrator:test --tests '*AnalyzeApkWorkflowTest'`
Expected: FAIL — `AnalysisResult` 4-arg constructor and `aiTriage` do not exist.

- [ ] **Step 3: Extend ReportConfig**

In `AnalysisPlan.java`, change the `ReportConfig` record:

```java
    public record ReportConfig(String htmlKey, String sarifKey, String aiTriageJsonKey, String aiTriageMdKey) {
    }
```

And in `forRules`, change the `new ReportConfig(...)` construction to:

```java
                new ReportConfig(
                        keys.rootKey() + "/report.html",
                        keys.rootKey() + "/report.sarif",
                        keys.rootKey() + "/ai-triage.json",
                        keys.rootKey() + "/ai-triage.md"));
```

- [ ] **Step 4: Extend AnalysisResult**

`AnalysisResult.java`:

```java
package com.oversecured.sast.orchestrator;

public record AnalysisResult(
        String htmlReportKey,
        String sarifReportKey,
        String aiTriageJsonKey,
        String aiTriageMdKey) {
}
```

- [ ] **Step 5: Update StartAnalysisCommand output**

In `cli/StartAnalysisCommand.java`, after the existing `sarif=` println (line ~57), add:

```java
        System.out.println("aiTriageJson=" + result.aiTriageJsonKey());
        System.out.println("aiTriageMd=" + result.aiTriageMdKey());
```

- [ ] **Step 6: Update StartAnalysisCommandTest fake**

In `StartAnalysisCommandTest.java` line ~52, update the fake's return:

```java
            return new AnalysisResult(
                    request.plan().report().htmlKey(),
                    request.plan().report().sarifKey(),
                    request.plan().report().aiTriageJsonKey(),
                    request.plan().report().aiTriageMdKey());
```

- [ ] **Step 7: Wire the workflow step**

In `AnalyzeApkWorkflowImpl.java`:

(a) Add the node constant after `REPORT`:

```java
    private static final String AI_TRIAGE = "ai-triage";
```

(b) Add the import:

```java
import com.oversecured.sast.orchestrator.activities.AiTriageActivityInput;
```

(c) Replace the report block + return (lines 107-112) with:

```java
        runStep(REPORT, "Building report.", () -> activities.report(new ReportActivityInput(
                plan.findingsKeysForReporter(),
                plan.report().htmlKey(),
                plan.report().sarifKey())));

        runStep(AI_TRIAGE, "Running AI triage.", () -> activities.aiTriage(new AiTriageActivityInput(
                plan.report().sarifKey(),
                plan.keys().sourcesDirKey(),
                plan.report().aiTriageJsonKey(),
                plan.report().aiTriageMdKey())));

        return new AnalysisResult(
                plan.report().htmlKey(),
                plan.report().sarifKey(),
                plan.report().aiTriageJsonKey(),
                plan.report().aiTriageMdKey());
```

(d) Add the node definition to `nodeDefinitions()`, after the `REPORT` entry:

```java
                new RunStatusBuilder.NodeDefinition(AI_TRIAGE, "AI Triage", "report"),
```

(Append after the existing `REPORT` `NodeDefinition` — adjust the trailing comma/`)` so the `List.of(...)` stays valid.)

- [ ] **Step 8: Run tests to verify they pass**

Run: `./gradlew :orchestrator:test --tests '*AnalyzeApkWorkflowTest' --tests '*StartAnalysisCommandTest' --tests '*AnalysisPlanTest'`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add orchestrator/src
git commit -m "feat(ai-triage): wire aiTriage into workflow, plan, result"
```

---

### Task 10: Full build, docs, integration verification

**Files:**
- Modify: `README.md` (env vars + step description)
- Test: full suite

- [ ] **Step 1: Document the env vars and step**

In `README.md`, find the pipeline/steps section and add a subsection (place near the reporter description):

```markdown
### AI Triage (sidecar)

After the report is built, an AI triage step (`apps/ai-triage`) reads the SARIF
report and decompiled sources in a LangChain4j tool-calling loop and writes
`ai-triage.json` + `ai-triage.md` with a per-finding verdict
(`exploitable` / `needs-review` / `safe`), re-judged severity, and a concrete
fix suggestion.

It is always-on and fail-soft: with no API key or on any error it writes an
empty sidecar and the pipeline still succeeds.

Configure via environment variables:

- `OPENROUTER_API_KEY` — OpenRouter API key (required to actually run the agent).
- `OPENROUTER_MODEL` — model id (default `anthropic/claude-3.5-sonnet`).
```

- [ ] **Step 2: Run the full module + orchestrator test suites**

Run: `./gradlew :apps:ai-triage:test :orchestrator:test`
Expected: PASS — all tests green.

- [ ] **Step 3: Full build**

Run: `./gradlew build`
Expected: BUILD SUCCESSFUL. (Confirms the new module + LangChain4j deps resolve and the whole project compiles.)

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs(ai-triage): document AI triage step + OpenRouter env vars"
```

---

## Self-Review Notes

- **Spec coverage:** sidecar JSON+MD (Tasks 5,6,9), one-agent-all-findings ReAct via `AiServices` + `@Tool` (Tasks 3,7), OpenRouter `baseUrl` (Task 7), always-on fail-soft (Task 6), after-report sequential placement (Task 9), SARIF input (Task 2), full prompt incl. example carried in spec (Task 4 references it; the `SYSTEM` constant embeds the instructions — the worked two-shot example from the spec MAY be appended to `TriagePrompt.SYSTEM` verbatim if desired, but is optional since structured output already constrains shape).
- **Verdict/severity vocab:** enforced by enums (Task 1) + prompt (Task 4).
- **Type consistency:** `StepResult.completed(nodeId, message, metrics, artifacts, findingsKeys, findingCount, severityCounts)` matches the live 7-arg overload used by `report`. `ArtifactRef(type, key)`, `FindingRef(ruleId, file, line)`, `ReportConfig` 4-arg, `AnalysisResult` 4-arg all consistent across tasks.
- **Open item for implementer:** confirm the LangChain4j 1.1.0 builder method name (`chatModel` vs `chatLanguageModel`) against the resolved jar (Task 7 note).
