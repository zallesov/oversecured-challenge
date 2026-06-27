# Manifest Misconfig (Step 5, fan-out) Implementation Plan

**Shared conventions:** [Shared Contracts and Naming Conventions](../reference/2026-06-27-shared-contracts-and-conventions.md)
**Logging:** [Logging Conventions](../reference/2026-06-27-logging.md)
**Error handling:** [Error Handling Conventions](../reference/2026-06-27-error-handling.md)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `apps/manifest-misconfig` — the rule-driven manifest misconfiguration analyzer with CLI `mscan --facts <facts.json> --rule <misconfig.yaml> --out <findings.json>`.

**Architecture:** A Gradle application module consumes shared `ManifestFacts`, `ComponentFact`, `IntentFilterFact`, `Severity`, `Finding`, `FindingsDoc`, and `Json` from `common`. Analyzer-owned YAML models live under `com.oversecured.sast.misconfig.model`; a small loader maps `rules/misconfig.yaml` into those models; `MisconfigAnalyzer` evaluates each requested check and emits analyzer-agnostic `FindingsDoc`. The analyzer reads `facts.json` only through the shared `ManifestFacts` schema, so every fact it needs must be produced by `apps/manifest-facts` and represented in `common`.

**Tech Stack:** Java 17; Gradle Groovy DSL; JUnit 5 + AssertJ; Jackson YAML; picocli 4.7.x; shared contracts from `:common`.

## Global Constraints

- Module path: `apps/manifest-misconfig`; Gradle project: `:apps:manifest-misconfig`.
- Package root: `com.oversecured.sast.misconfig`.
- Analyzer-owned model package: `com.oversecured.sast.misconfig.model`.
- CLI contract: `mscan --facts <facts.json> --rule <misconfig.yaml> --out <findings.json>`.
- Output contract: `FindingsDoc` with `analyzer` exactly `"manifest-misconfig"` and `Finding` objects from `com.oversecured.sast.common`.
- Shared input contract: `ManifestFacts(String packageName, List<ComponentFact> components, List<String> permissions)`, `ComponentFact(String name, String type, boolean exported, List<IntentFilterFact> intentFilters, boolean grantUriPermissions, String permission)`, `IntentFilterFact(List<String> actions, List<String> schemes, List<String> hosts)`.
- Do not duplicate shared models and do not create `com.oversecured.sast.common.model`.
- YAML uses snake_case and lowercase severity values; the loader must enable `PropertyNamingStrategies.SNAKE_CASE` and case-insensitive enum deserialization.
- `provider_grant_uri_permissions`: emit for provider components where `ComponentFact.grantUriPermissions()` is true.
- `weak_host_validation`: emit for exported components with deep-link intent filters whose host is absent, empty, `"*"`, or starts with `"*."`. Source-level checks such as `host.endsWith("example.com")` are modeled by the taint engine as incomplete sanitizers, not by this manifest-only analyzer.
- Findings are deterministic: preserve rule file order, then manifest component order; sort nothing unless a test explicitly expects stable order from insertion order.

---

## File Structure

```
challenge/
└── apps/manifest-misconfig/
    ├── build.gradle
    └── src/
        ├── main/java/com/oversecured/sast/misconfig/
        │   ├── Main.java                         # tiny entrypoint delegates to MisconfigCommand
        │   ├── MisconfigCommand.java             # picocli CLI + file I/O
        │   ├── MisconfigApp.java                 # library API: analyze(facts, rule, out)
        │   ├── MisconfigAnalyzer.java            # ManifestFacts + MisconfigRuleFile -> FindingsDoc
        │   ├── MisconfigRuleLoader.java          # YAML -> MisconfigRuleFile
        │   └── model/
        │       ├── MisconfigRuleFile.java         # analyzer-owned YAML root model
        │       └── MisconfigCheck.java            # analyzer-owned check model
        └── test/java/com/oversecured/sast/misconfig/
            ├── MisconfigRuleLoaderTest.java
            ├── MisconfigAnalyzerTest.java
            └── MisconfigCommandTest.java
```

**Responsibilities:** model classes are only YAML shape + getters; `MisconfigRuleLoader` owns YAML mapper configuration; `MisconfigAnalyzer` owns check semantics over shared `ManifestFacts`; `MisconfigCommand` owns CLI parsing and path I/O.

---

## Task 1: Gradle application scaffolding

**Files:**
- Modify: `apps/manifest-misconfig/build.gradle`
- Create: `apps/manifest-misconfig/src/main/java/com/oversecured/sast/misconfig/Main.java`
- Create: `apps/manifest-misconfig/src/main/java/com/oversecured/sast/misconfig/MisconfigCommand.java`
- Test: `apps/manifest-misconfig/src/test/java/com/oversecured/sast/misconfig/MisconfigCommandTest.java`

**Interfaces:**
- Consumes: root `settings.gradle` and root dependency versions from the common plan.
- Produces: runnable application module whose `run` task can load `com.oversecured.sast.misconfig.Main`.

- [ ] **Step 1: Write the failing smoke test**

Create `apps/manifest-misconfig/src/test/java/com/oversecured/sast/misconfig/MisconfigCommandTest.java`:

```java
package com.oversecured.sast.misconfig;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import picocli.CommandLine;

class MisconfigCommandTest {

    @Test
    void commandNameIsMscan() {
        CommandLine cmd = new CommandLine(new MisconfigCommand());
        assertThat(cmd.getCommandName()).isEqualTo("mscan");
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `./gradlew :apps:manifest-misconfig:test --tests 'com.oversecured.sast.misconfig.MisconfigCommandTest.commandNameIsMscan'`
Expected: FAIL with compilation errors for missing `MisconfigCommand` or missing picocli dependency.

- [ ] **Step 3: Implement minimal application wiring**

Replace `apps/manifest-misconfig/build.gradle` with:

```groovy
plugins {
    id 'application'
}

dependencies {
    implementation project(':common')
    implementation "com.fasterxml.jackson.core:jackson-databind:${rootProject.ext.jacksonVersion}"
    implementation "com.fasterxml.jackson.dataformat:jackson-dataformat-yaml:${rootProject.ext.jacksonVersion}"
    implementation "info.picocli:picocli:${rootProject.ext.picocliVersion}"
    annotationProcessor "info.picocli:picocli-codegen:${rootProject.ext.picocliVersion}"
}

application {
    mainClass = 'com.oversecured.sast.misconfig.Main'
}
```

Create `apps/manifest-misconfig/src/main/java/com/oversecured/sast/misconfig/Main.java`:

```java
package com.oversecured.sast.misconfig;

import picocli.CommandLine;

public final class Main {
    private Main() {
    }

    public static void main(String[] args) {
        int exit = new CommandLine(new MisconfigCommand()).execute(args);
        System.exit(exit);
    }
}
```

Create `apps/manifest-misconfig/src/main/java/com/oversecured/sast/misconfig/MisconfigCommand.java`:

```java
package com.oversecured.sast.misconfig;

import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(
        name = "mscan",
        mixinStandardHelpOptions = true,
        description = "Analyze Android manifest facts for rule-driven misconfigurations.")
public class MisconfigCommand implements Callable<Integer> {

    @Option(names = "--facts", required = true, description = "Path to facts.json")
    java.nio.file.Path factsPath;

    @Option(names = "--rule", required = true, description = "Path to misconfig.yaml")
    java.nio.file.Path rulePath;

    @Option(names = "--out", required = true, description = "Path to findings.json")
    java.nio.file.Path outPath;

    @Override
    public Integer call() {
        throw new UnsupportedOperationException("analysis wiring is added in Task 5");
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `./gradlew :apps:manifest-misconfig:test --tests 'com.oversecured.sast.misconfig.MisconfigCommandTest.commandNameIsMscan'`
Expected: PASS (1 test).

- [ ] **Step 5: Commit**

```bash
git add apps/manifest-misconfig/build.gradle apps/manifest-misconfig/src/main/java/com/oversecured/sast/misconfig/Main.java apps/manifest-misconfig/src/main/java/com/oversecured/sast/misconfig/MisconfigCommand.java apps/manifest-misconfig/src/test/java/com/oversecured/sast/misconfig/MisconfigCommandTest.java
git commit -m "build(manifest-misconfig): scaffold mscan application module"
```

---

## Task 2: Analyzer-owned YAML model with rules-plan-compatible getters

**Files:**
- Create: `apps/manifest-misconfig/src/main/java/com/oversecured/sast/misconfig/model/MisconfigRuleFile.java`
- Create: `apps/manifest-misconfig/src/main/java/com/oversecured/sast/misconfig/model/MisconfigCheck.java`
- Test: `apps/manifest-misconfig/src/test/java/com/oversecured/sast/misconfig/MisconfigRuleLoaderTest.java`

**Interfaces:**
- Produces: `MisconfigRuleFile(int version, List<MisconfigCheck> checks)` with `getVersion()` and `getChecks()`.
- Produces: `MisconfigCheck(String id, Severity severity, String cwe, String kind, String message)` with `getId()`, `getSeverity()`, `getCwe()`, `getKind()`, and `getMessage()`.
- These getters are required by `docs/superpowers/plans/2026-06-27-rules.md`.

- [ ] **Step 1: Write the failing model test**

Create `apps/manifest-misconfig/src/test/java/com/oversecured/sast/misconfig/MisconfigRuleLoaderTest.java`:

```java
package com.oversecured.sast.misconfig;

import static org.assertj.core.api.Assertions.assertThat;

import com.oversecured.sast.common.Severity;
import com.oversecured.sast.misconfig.model.MisconfigCheck;
import com.oversecured.sast.misconfig.model.MisconfigRuleFile;
import java.util.List;
import org.junit.jupiter.api.Test;

class MisconfigRuleLoaderTest {

    @Test
    void modelExposesRulesPlanCompatibleGetters() {
        MisconfigCheck check = new MisconfigCheck(
                "exported_provider",
                Severity.ERROR,
                "CWE-926",
                "exported-content-provider",
                "ContentProvider is exported");
        MisconfigRuleFile file = new MisconfigRuleFile(1, List.of(check));

        assertThat(file.getVersion()).isEqualTo(1);
        assertThat(file.getChecks()).containsExactly(check);
        assertThat(check.getId()).isEqualTo("exported_provider");
        assertThat(check.getSeverity()).isEqualTo(Severity.ERROR);
        assertThat(check.getCwe()).isEqualTo("CWE-926");
        assertThat(check.getKind()).isEqualTo("exported-content-provider");
        assertThat(check.getMessage()).isEqualTo("ContentProvider is exported");
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `./gradlew :apps:manifest-misconfig:test --tests 'com.oversecured.sast.misconfig.MisconfigRuleLoaderTest.modelExposesRulesPlanCompatibleGetters'`
Expected: FAIL with `package com.oversecured.sast.misconfig.model does not exist`.

- [ ] **Step 3: Implement the model classes**

Create `apps/manifest-misconfig/src/main/java/com/oversecured/sast/misconfig/model/MisconfigRuleFile.java`:

```java
package com.oversecured.sast.misconfig.model;

import java.util.ArrayList;
import java.util.List;

public class MisconfigRuleFile {
    private int version;
    private List<MisconfigCheck> checks = new ArrayList<>();

    public MisconfigRuleFile() {
    }

    public MisconfigRuleFile(int version, List<MisconfigCheck> checks) {
        this.version = version;
        this.checks = checks == null ? List.of() : List.copyOf(checks);
    }

    public int getVersion() {
        return version;
    }

    public void setVersion(int version) {
        this.version = version;
    }

    public List<MisconfigCheck> getChecks() {
        return checks;
    }

    public void setChecks(List<MisconfigCheck> checks) {
        this.checks = checks == null ? List.of() : List.copyOf(checks);
    }
}
```

Create `apps/manifest-misconfig/src/main/java/com/oversecured/sast/misconfig/model/MisconfigCheck.java`:

```java
package com.oversecured.sast.misconfig.model;

import com.oversecured.sast.common.Severity;

public class MisconfigCheck {
    private String id;
    private Severity severity;
    private String cwe;
    private String kind;
    private String message;

    public MisconfigCheck() {
    }

    public MisconfigCheck(String id, Severity severity, String cwe, String kind, String message) {
        this.id = id;
        this.severity = severity;
        this.cwe = cwe;
        this.kind = kind;
        this.message = message;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public Severity getSeverity() {
        return severity;
    }

    public void setSeverity(Severity severity) {
        this.severity = severity;
    }

    public String getCwe() {
        return cwe;
    }

    public void setCwe(String cwe) {
        this.cwe = cwe;
    }

    public String getKind() {
        return kind;
    }

    public void setKind(String kind) {
        this.kind = kind;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `./gradlew :apps:manifest-misconfig:test --tests 'com.oversecured.sast.misconfig.MisconfigRuleLoaderTest.modelExposesRulesPlanCompatibleGetters'`
Expected: PASS (1 test).

- [ ] **Step 5: Commit**

```bash
git add apps/manifest-misconfig/src/main/java/com/oversecured/sast/misconfig/model/MisconfigRuleFile.java apps/manifest-misconfig/src/main/java/com/oversecured/sast/misconfig/model/MisconfigCheck.java apps/manifest-misconfig/src/test/java/com/oversecured/sast/misconfig/MisconfigRuleLoaderTest.java
git commit -m "feat(manifest-misconfig): add YAML rule model with getter API"
```

---

## Task 3: YAML rule loader

**Files:**
- Create: `apps/manifest-misconfig/src/main/java/com/oversecured/sast/misconfig/MisconfigRuleLoader.java`
- Modify: `apps/manifest-misconfig/src/test/java/com/oversecured/sast/misconfig/MisconfigRuleLoaderTest.java`

**Interfaces:**
- Consumes: `MisconfigRuleFile`, `MisconfigCheck`, `Severity`.
- Produces: `MisconfigRuleLoader.load(Path)` and `MisconfigRuleLoader.load(byte[])`.

- [ ] **Step 1: Add failing YAML loader test**

Append this test to `MisconfigRuleLoaderTest`:

```java
    @Test
    void loadsSnakeCaseYamlWithLowercaseSeverity() {
        String yaml = """
                version: 1
                checks:
                  - id: exported_without_permission
                    severity: warning
                    cwe: CWE-926
                    kind: exported-component-no-permission
                    message: "Component is exported without permission"
                """;

        MisconfigRuleFile file = MisconfigRuleLoader.load(yaml.getBytes(java.nio.charset.StandardCharsets.UTF_8));

        assertThat(file.getVersion()).isEqualTo(1);
        assertThat(file.getChecks()).hasSize(1);
        MisconfigCheck check = file.getChecks().get(0);
        assertThat(check.getId()).isEqualTo("exported_without_permission");
        assertThat(check.getSeverity()).isEqualTo(Severity.WARNING);
        assertThat(check.getKind()).isEqualTo("exported-component-no-permission");
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `./gradlew :apps:manifest-misconfig:test --tests 'com.oversecured.sast.misconfig.MisconfigRuleLoaderTest.loadsSnakeCaseYamlWithLowercaseSeverity'`
Expected: FAIL with `cannot find symbol: variable MisconfigRuleLoader`.

- [ ] **Step 3: Implement the YAML loader**

Create `apps/manifest-misconfig/src/main/java/com/oversecured/sast/misconfig/MisconfigRuleLoader.java`:

```java
package com.oversecured.sast.misconfig;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.oversecured.sast.misconfig.model.MisconfigRuleFile;
import java.nio.file.Files;
import java.nio.file.Path;

public final class MisconfigRuleLoader {
    private static final ObjectMapper YAML = new ObjectMapper(new YAMLFactory())
            .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_ENUMS, true);

    private MisconfigRuleLoader() {
    }

    public static MisconfigRuleFile load(Path path) {
        try {
            return load(Files.readAllBytes(path));
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to read misconfig rule file: " + path, e);
        }
    }

    public static MisconfigRuleFile load(byte[] yaml) {
        try {
            MisconfigRuleFile file = YAML.readValue(yaml, MisconfigRuleFile.class);
            validate(file);
            return file;
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse misconfig rule YAML", e);
        }
    }

    private static void validate(MisconfigRuleFile file) {
        if (file.getVersion() != 1) {
            throw new IllegalArgumentException("Unsupported misconfig rule version: " + file.getVersion());
        }
        if (file.getChecks() == null || file.getChecks().isEmpty()) {
            throw new IllegalArgumentException("misconfig rule file must contain at least one check");
        }
        for (var check : file.getChecks()) {
            if (isBlank(check.getId()) || check.getSeverity() == null || isBlank(check.getCwe())
                    || isBlank(check.getKind()) || isBlank(check.getMessage())) {
                throw new IllegalArgumentException("misconfig check has missing required fields");
            }
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
```

- [ ] **Step 4: Run loader tests**

Run: `./gradlew :apps:manifest-misconfig:test --tests 'com.oversecured.sast.misconfig.MisconfigRuleLoaderTest'`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add apps/manifest-misconfig/src/main/java/com/oversecured/sast/misconfig/MisconfigRuleLoader.java apps/manifest-misconfig/src/test/java/com/oversecured/sast/misconfig/MisconfigRuleLoaderTest.java
git commit -m "feat(manifest-misconfig): load misconfig YAML rule files"
```

---

## Task 4: Analyzer semantics for the four `misconfig.yaml` checks

**Files:**
- Create: `apps/manifest-misconfig/src/main/java/com/oversecured/sast/misconfig/MisconfigAnalyzer.java`
- Test: `apps/manifest-misconfig/src/test/java/com/oversecured/sast/misconfig/MisconfigAnalyzerTest.java`

**Interfaces:**
- Consumes: `ManifestFacts`, `ComponentFact`, `IntentFilterFact`, `Finding`, `FindingsDoc`, `FlowStep`, `Severity`, `Json`, `MisconfigRuleFile`, `MisconfigCheck`.
- Produces: `MisconfigAnalyzer.analyze(ManifestFacts facts, MisconfigRuleFile rules)`.

- [ ] **Step 1: Write failing analyzer tests**

Create `apps/manifest-misconfig/src/test/java/com/oversecured/sast/misconfig/MisconfigAnalyzerTest.java`:

```java
package com.oversecured.sast.misconfig;

import static org.assertj.core.api.Assertions.assertThat;

import com.oversecured.sast.common.ComponentFact;
import com.oversecured.sast.common.Finding;
import com.oversecured.sast.common.FindingsDoc;
import com.oversecured.sast.common.IntentFilterFact;
import com.oversecured.sast.common.Json;
import com.oversecured.sast.common.ManifestFacts;
import com.oversecured.sast.common.Severity;
import com.oversecured.sast.misconfig.model.MisconfigCheck;
import com.oversecured.sast.misconfig.model.MisconfigRuleFile;
import java.util.List;
import org.junit.jupiter.api.Test;

class MisconfigAnalyzerTest {

    @Test
    void reportsExportedComponentWithoutPermission() {
        ManifestFacts facts = new ManifestFacts(
                "oversecured.ovaa",
                List.of(new ComponentFact("oversecured.ovaa.DeeplinkActivity", "activity", true, List.of(), false, null)),
                List.of());
        FindingsDoc doc = new MisconfigAnalyzer().analyze(facts, rules("exported_without_permission"));

        assertThat(doc.analyzer()).isEqualTo("manifest-misconfig");
        assertThat(doc.findings()).extracting(Finding::ruleId).containsExactly("exported_without_permission");
        Finding finding = doc.findings().get(0);
        assertThat(finding.severity()).isEqualTo(Severity.WARNING);
        assertThat(finding.vulnerabilityClass()).isEqualTo("exported-component-no-permission");
        assertThat(finding.flow().get(0).label()).contains("oversecured.ovaa.DeeplinkActivity");
    }

    @Test
    void reportsExportedProviderAndGrantUriPermissions() {
        ManifestFacts facts = new ManifestFacts(
                "oversecured.ovaa",
                List.of(new ComponentFact("oversecured.ovaa.FileProvider", "provider", true, List.of(), true, null)),
                List.of());

        FindingsDoc doc = new MisconfigAnalyzer().analyze(
                facts,
                rules("exported_provider", "provider_grant_uri_permissions"));

        assertThat(doc.findings()).extracting(Finding::ruleId)
                .containsExactly("exported_provider", "provider_grant_uri_permissions");
    }

    @Test
    void reportsWeakHostValidationFromManifestFacts() {
        ManifestFacts facts = new ManifestFacts(
                "oversecured.ovaa",
                List.of(
                        new ComponentFact(
                                "oversecured.ovaa.WildcardActivity",
                                "activity",
                                true,
                                List.of(new IntentFilterFact(
                                        List.of("android.intent.action.VIEW"),
                                        List.of("https"),
                                        List.of("*.example.com"))),
                                false,
                                null),
                        new ComponentFact(
                                "oversecured.ovaa.StrictHostActivity",
                                "activity",
                                true,
                                List.of(new IntentFilterFact(
                                        List.of("android.intent.action.VIEW"),
                                        List.of("https"),
                                        List.of("example.com"))),
                                false,
                                null)));

        FindingsDoc doc = new MisconfigAnalyzer().analyze(facts, rules("weak_host_validation"));

        assertThat(doc.findings()).extracting(Finding::ruleId)
                .containsExactly("weak_host_validation");
    }

    @Test
    void doesNotReportGrantUriWhenGrantFlagIsFalse() {
        ManifestFacts facts = new ManifestFacts(
                "oversecured.ovaa",
                List.of(new ComponentFact("oversecured.ovaa.FileProvider", "provider", true, List.of(), false, null)),
                List.of());

        FindingsDoc doc = new MisconfigAnalyzer().analyze(
                facts,
                rules("provider_grant_uri_permissions"));

        assertThat(doc.findings()).isEmpty();
    }

    private static MisconfigRuleFile rules(String... ids) {
        java.util.Map<String, MisconfigCheck> all = java.util.Map.of(
                "exported_without_permission", new MisconfigCheck(
                        "exported_without_permission", Severity.WARNING, "CWE-926",
                        "exported-component-no-permission", "Component is exported without permission"),
                "exported_provider", new MisconfigCheck(
                        "exported_provider", Severity.ERROR, "CWE-926",
                        "exported-content-provider", "ContentProvider is exported"),
                "provider_grant_uri_permissions", new MisconfigCheck(
                        "provider_grant_uri_permissions", Severity.WARNING, "CWE-266",
                        "provider-grant-uri-permissions", "ContentProvider grants URI permissions"),
                "weak_host_validation", new MisconfigCheck(
                        "weak_host_validation", Severity.ERROR, "CWE-601",
                        "weak-host-validation", "Weak deeplink host validation"));
        return new MisconfigRuleFile(1, java.util.Arrays.stream(ids).map(all::get).toList());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `./gradlew :apps:manifest-misconfig:test --tests 'com.oversecured.sast.misconfig.MisconfigAnalyzerTest'`
Expected: FAIL with missing `MisconfigAnalyzer`.

- [ ] **Step 3: Implement the analyzer**

Create `apps/manifest-misconfig/src/main/java/com/oversecured/sast/misconfig/MisconfigAnalyzer.java`:

```java
package com.oversecured.sast.misconfig;

import com.oversecured.sast.common.ComponentFact;
import com.oversecured.sast.common.Finding;
import com.oversecured.sast.common.FindingsDoc;
import com.oversecured.sast.common.FlowStep;
import com.oversecured.sast.common.IntentFilterFact;
import com.oversecured.sast.common.ManifestFacts;
import com.oversecured.sast.misconfig.model.MisconfigCheck;
import com.oversecured.sast.misconfig.model.MisconfigRuleFile;
import java.util.ArrayList;
import java.util.List;

public class MisconfigAnalyzer {

    public FindingsDoc analyze(ManifestFacts facts, MisconfigRuleFile rules) {
        List<Finding> findings = new ArrayList<>();
        for (MisconfigCheck check : rules.getChecks()) {
            for (ComponentFact component : facts.components()) {
                if (matches(check.getId(), component)) {
                    findings.add(toFinding(check, component, notes(check.getId(), component)));
                }
            }
        }
        return new FindingsDoc("manifest-misconfig", List.copyOf(findings));
    }

    private boolean matches(String checkId, ComponentFact component) {
        return switch (checkId) {
            case "exported_without_permission" -> component.exported() && isBlank(component.permission());
            case "exported_provider" -> component.exported() && "provider".equals(component.type());
            case "provider_grant_uri_permissions" ->
                    "provider".equals(component.type()) && component.grantUriPermissions();
            case "weak_host_validation" -> component.exported()
                    && hasWeakManifestHost(component);
            default -> false;
        };
    }

    private Finding toFinding(MisconfigCheck check, ComponentFact component, List<String> notes) {
        return new Finding(
                check.getId(),
                check.getKind(),
                check.getSeverity(),
                check.getMessage(),
                check.getCwe(),
                "M1",
                List.of(new FlowStep("AndroidManifest.xml", 0,
                        component.type() + " " + component.name() + " matches " + check.getId())),
                notes);
    }

    private List<String> notes(String checkId, ComponentFact component) {
        List<String> notes = new ArrayList<>();
        if ("provider_grant_uri_permissions".equals(checkId)) {
            notes.add("fact: grantUriPermissions=true");
        }
        if (isBlank(component.permission())) {
            notes.add("component-permission: none");
        } else {
            notes.add("component-permission: " + component.permission());
        }
        return List.copyOf(notes);
    }

    private boolean hasWeakManifestHost(ComponentFact component) {
        for (IntentFilterFact filter : component.intentFilters()) {
            if (filter.schemes().isEmpty()) {
                continue;
            }
            if (filter.hosts().isEmpty()) {
                return true;
            }
            for (String host : filter.hosts()) {
                if (isBlank(host) || "*".equals(host) || host.startsWith("*.")) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
```

- [ ] **Step 4: Run analyzer tests**

Run: `./gradlew :apps:manifest-misconfig:test --tests 'com.oversecured.sast.misconfig.MisconfigAnalyzerTest'`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add apps/manifest-misconfig/src/main/java/com/oversecured/sast/misconfig/MisconfigAnalyzer.java apps/manifest-misconfig/src/test/java/com/oversecured/sast/misconfig/MisconfigAnalyzerTest.java
git commit -m "feat(manifest-misconfig): analyze exported and deeplink manifest checks"
```

---

## Task 5: CLI file I/O and `findings.json` output

**Files:**
- Create: `apps/manifest-misconfig/src/main/java/com/oversecured/sast/misconfig/MisconfigApp.java`
- Modify: `apps/manifest-misconfig/src/main/java/com/oversecured/sast/misconfig/MisconfigCommand.java`
- Modify: `apps/manifest-misconfig/src/test/java/com/oversecured/sast/misconfig/MisconfigCommandTest.java`

**Interfaces:**
- Consumes: `Json.read(byte[], ManifestFacts.class)`, `MisconfigRuleLoader.load(Path)`, `MisconfigAnalyzer.analyze(...)`, `Json.writeBytes(FindingsDoc)`.
- Produces: `MisconfigApp.analyze(Path factsJson, Path ruleYaml, Path findingsJson) throws IOException` for orchestrator use and `findings.json` at `--out`.

- [ ] **Step 1: Add failing CLI integration test**

Append this test to `MisconfigCommandTest`:

```java
    @org.junit.jupiter.api.Test
    void commandWritesFindingsJson() throws Exception {
        java.nio.file.Path dir = java.nio.file.Files.createTempDirectory("mscan-test");
        java.nio.file.Path facts = dir.resolve("facts.json");
        java.nio.file.Path rule = dir.resolve("misconfig.yaml");
        java.nio.file.Path out = dir.resolve("findings.json");

        java.nio.file.Files.writeString(facts, """
                {
                  "packageName": "oversecured.ovaa",
	                  "components": [
	                    {"name":"oversecured.ovaa.DeeplinkActivity","type":"activity","exported":true,
	                     "intentFilters":[],"grantUriPermissions":false,"permission":null}
                  ],
                  "permissions": []
                }
                """);
        java.nio.file.Files.writeString(rule, """
                version: 1
                checks:
                  - id: exported_without_permission
                    severity: warning
                    cwe: CWE-926
                    kind: exported-component-no-permission
                    message: "Component is exported without permission"
                """);

        int exit = new CommandLine(new MisconfigCommand()).execute(
                "--facts", facts.toString(),
                "--rule", rule.toString(),
                "--out", out.toString());

        assertThat(exit).isEqualTo(0);
        assertThat(java.nio.file.Files.exists(out)).isTrue();
        com.oversecured.sast.common.FindingsDoc doc = com.oversecured.sast.common.Json.read(
                java.nio.file.Files.readAllBytes(out),
                com.oversecured.sast.common.FindingsDoc.class);
        assertThat(doc.analyzer()).isEqualTo("manifest-misconfig");
        assertThat(doc.findings()).extracting(com.oversecured.sast.common.Finding::ruleId)
                .containsExactly("exported_without_permission");
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `./gradlew :apps:manifest-misconfig:test --tests 'com.oversecured.sast.misconfig.MisconfigCommandTest.commandWritesFindingsJson'`
Expected: FAIL with `UnsupportedOperationException: analysis wiring is added in Task 5`.

- [ ] **Step 3: Add the library API and wire the CLI**

Create `apps/manifest-misconfig/src/main/java/com/oversecured/sast/misconfig/MisconfigApp.java`:

```java
package com.oversecured.sast.misconfig;

import com.oversecured.sast.common.FindingsDoc;
import com.oversecured.sast.common.Json;
import com.oversecured.sast.common.ManifestFacts;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public final class MisconfigApp {

    public FindingsDoc analyze(Path factsJson, Path ruleYaml, Path findingsJson) throws IOException {
        ManifestFacts facts = Json.read(Files.readAllBytes(factsJson), ManifestFacts.class);
        var rules = MisconfigRuleLoader.load(ruleYaml);
        var findings = new MisconfigAnalyzer().analyze(facts, rules);

        Path parent = findingsJson.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.write(findingsJson, Json.writeBytes(findings));
        return findings;
    }
}
```

Replace `call()` in `MisconfigCommand.java` with:

```java
    @Override
    public Integer call() {
        try {
            new MisconfigApp().analyze(factsPath, rulePath, outPath);
            return 0;
        } catch (Exception e) {
            System.err.println("mscan failed: " + e.getMessage());
            return 1;
        }
    }
```

- [ ] **Step 4: Run CLI tests**

Run: `./gradlew :apps:manifest-misconfig:test --tests 'com.oversecured.sast.misconfig.MisconfigCommandTest'`
Expected: PASS (2 tests).

- [ ] **Step 5: Verify the application entrypoint**

Run: `./gradlew :apps:manifest-misconfig:run --args='--help'`
Expected: PASS and stdout contains `Usage: mscan --facts=<factsPath> --out=<outPath> --rule=<rulePath>`.

- [ ] **Step 6: Commit**

```bash
git add apps/manifest-misconfig/src/main/java/com/oversecured/sast/misconfig/MisconfigApp.java apps/manifest-misconfig/src/main/java/com/oversecured/sast/misconfig/MisconfigCommand.java apps/manifest-misconfig/src/test/java/com/oversecured/sast/misconfig/MisconfigCommandTest.java
git commit -m "feat(manifest-misconfig): wire mscan CLI to findings output"
```

---

## Task 6: End-to-end validation with `rules/misconfig.yaml`

**Files:**
- Modify: `apps/manifest-misconfig/src/test/java/com/oversecured/sast/misconfig/MisconfigCommandTest.java`

**Interfaces:**
- Consumes: `rules/misconfig.yaml` from `docs/superpowers/plans/2026-06-27-rules.md`.
- Produces: an end-to-end assertion that the real rule file drives `mscan` and emits the expected checks.

- [ ] **Step 1: Add the real-rule-file end-to-end test**

Append this helper and test to `MisconfigCommandTest`:

```java
    @org.junit.jupiter.api.Test
    void commandRunsAgainstRepositoryMisconfigYaml() throws Exception {
        java.nio.file.Path rule = findRepoRoot().resolve("rules/misconfig.yaml");
        java.nio.file.Path dir = java.nio.file.Files.createTempDirectory("mscan-real-rules");
        java.nio.file.Path facts = dir.resolve("facts.json");
        java.nio.file.Path out = dir.resolve("findings-misconfig.json");

        java.nio.file.Files.writeString(facts, """
                {
                  "packageName": "oversecured.ovaa",
                  "components": [
                    {"name":"oversecured.ovaa.DeeplinkActivity","type":"activity","exported":true,
	                     "intentFilters":[{"actions":["android.intent.action.VIEW"],"schemes":["https"],"hosts":["*.example.com"]}],
	                     "grantUriPermissions":false,"permission":null},
                    {"name":"oversecured.ovaa.FileProvider","type":"provider","exported":true,
                     "intentFilters":[],"permission":null,"grantUriPermissions":true}
                  ],
                  "permissions": []
                }
                """);

        int exit = new CommandLine(new MisconfigCommand()).execute(
                "--facts", facts.toString(),
                "--rule", rule.toString(),
                "--out", out.toString());

        assertThat(exit).isEqualTo(0);
        com.oversecured.sast.common.FindingsDoc doc = com.oversecured.sast.common.Json.read(
                java.nio.file.Files.readAllBytes(out),
                com.oversecured.sast.common.FindingsDoc.class);
        assertThat(doc.findings()).extracting(com.oversecured.sast.common.Finding::ruleId)
                .contains(
                        "exported_without_permission",
                        "exported_provider",
                        "provider_grant_uri_permissions",
                        "weak_host_validation");
    }

    private static java.nio.file.Path findRepoRoot() {
        java.nio.file.Path dir = java.nio.file.Path.of("").toAbsolutePath();
        while (dir != null) {
            if (java.nio.file.Files.isRegularFile(dir.resolve("settings.gradle"))) {
                return dir;
            }
            dir = dir.getParent();
        }
        throw new IllegalStateException("could not locate repo root");
    }
```

- [ ] **Step 2: Run the test to verify the cross-plan dependency**

Run: `./gradlew :apps:manifest-misconfig:test --tests 'com.oversecured.sast.misconfig.MisconfigCommandTest.commandRunsAgainstRepositoryMisconfigYaml'`
Expected before the rules plan is implemented: FAIL with missing `rules/misconfig.yaml`. Expected after the rules plan is implemented: PASS and output contains four rule IDs listed above.

- [ ] **Step 3: Run the full module test suite**

Run: `./gradlew :apps:manifest-misconfig:test`
Expected: PASS after `rules/misconfig.yaml` exists; the suite covers model getters, YAML loading, analyzer semantics, CLI output, and real rule-file integration.

- [ ] **Step 4: Run the application with explicit fixture files**

Create temporary files outside the repo:

```bash
tmpdir="$(mktemp -d)"
cat > "$tmpdir/facts.json" <<'JSON'
{
  "packageName": "oversecured.ovaa",
  "components": [
    {"name":"oversecured.ovaa.DeeplinkActivity","type":"activity","exported":true,
     "intentFilters":[{"actions":["android.intent.action.VIEW"],"schemes":["https"],"hosts":["*.example.com"]}],
     "permission":null},
    {"name":"oversecured.ovaa.FileProvider","type":"provider","exported":true,
     "intentFilters":[],"permission":null,"grantUriPermissions":true}
  ],
  "permissions": []
}
JSON
./gradlew :apps:manifest-misconfig:run --args="--facts $tmpdir/facts.json --rule rules/misconfig.yaml --out $tmpdir/findings.json"
cat "$tmpdir/findings.json"
```

Expected: command exits 0; JSON contains `"analyzer" : "manifest-misconfig"` and findings with rule IDs `exported_without_permission`, `exported_provider`, `provider_grant_uri_permissions`, and `weak_host_validation`.

- [ ] **Step 5: Commit**

```bash
git add apps/manifest-misconfig/src/test/java/com/oversecured/sast/misconfig/MisconfigCommandTest.java
git commit -m "test(manifest-misconfig): validate mscan with repository misconfig rules"
```

---

## Task 7: Final verification

**Files:**
- No new files.

- [ ] **Step 1: Run focused module verification**

Run: `./gradlew :apps:manifest-misconfig:clean :apps:manifest-misconfig:test`
Expected: PASS; all tests in `MisconfigRuleLoaderTest`, `MisconfigAnalyzerTest`, and `MisconfigCommandTest` pass.

- [ ] **Step 2: Run integration-adjacent validation from the rules plan**

Run: `./gradlew :apps:taint:test --tests 'com.oversecured.sast.taint.rules.RulesValidationTest.misconfigFileHasTheFourChecks'`
Expected after rules and taint model plans are implemented: PASS; `MisconfigRuleFile.getChecks()` and `MisconfigCheck.getId()` are compatible with the rules validation test.

- [ ] **Step 3: Run build for dependent shared modules**

Run: `./gradlew :common:test :apps:manifest-misconfig:test`
Expected: PASS; confirms `common` JSON/facts contracts and the analyzer module agree.

- [ ] **Step 4: Commit any final test-only adjustments**

If Step 1-3 required changes, commit them:

```bash
git add apps/manifest-misconfig
git commit -m "test(manifest-misconfig): complete analyzer verification coverage"
```

If Step 1-3 required no changes, do not create an empty commit.

---

## Self-Review Checklist

- Spec coverage: `:apps:manifest-misconfig`, package root `com.oversecured.sast.misconfig`, CLI `mscan --facts --rule --out`, shared `FindingsDoc` output, and checks `exported_without_permission`, `exported_provider`, `provider_grant_uri_permissions`, `weak_host_validation` are covered by Tasks 1-6.
- Shared contracts: uses `ManifestFacts`, `ComponentFact`, `IntentFilterFact`, `Severity`, `Json`, `Finding`, and `FindingsDoc` from `com.oversecured.sast.common`; analyzer rule models stay in `com.oversecured.sast.misconfig.model`.
- Rules-plan compatibility: `MisconfigRuleFile` and `MisconfigCheck` expose the required `getChecks()` and `getId()` getters, plus complete getters for all YAML fields.
- Weak-host behavior: manifest-facts-based behavior is explicit; source-level `endsWith` / `contains` detection is handled by the taint engine as an incomplete sanitizer, not by this manifest-only analyzer.
- Provider grant behavior: `ComponentFact.grantUriPermissions()` is a first-class shared fact produced by `apps/manifest-facts`; false means no finding.
- Completeness scan: all file names, commands, model names, and rule IDs are concrete.
