# Decompiler (Step 1) Implementation Plan

**Shared conventions:** [Shared Contracts and Naming Conventions](../reference/2026-06-27-shared-contracts-and-conventions.md)
**Logging:** [Logging Conventions](../reference/2026-06-27-logging.md)
**Error handling:** [Error Handling Conventions](../reference/2026-06-27-error-handling.md)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `apps/decompiler` — a picocli `decompile --apk <file> --out <dir>` CLI that wraps embedded `jadx-core` to turn an Android APK into a `.java` source tree plus the decoded `AndroidManifest.xml`, with clear non-zero-exit error handling for missing/corrupt APKs.

**Architecture:** This is the first runnable step of the SAST pipeline (spec §3.1). It is built as a Gradle multi-module project bootstrapped here (root build, wrapper, `common`, `apps:decompiler`). A pure-Java `Decompiler` service performs input validation + jadx invocation and returns a `DecompileResult`; a thin `DecompilerCli` (picocli `Callable<Integer>`) wraps it and maps failures to exit code 1. `--out` is the output directory itself (per spec CLI `decompile --apk a.apk --out sources/`): jadx writes the `.java` package tree and the decoded `AndroidManifest.xml` directly into it. The decompiler uses plain filesystem paths (spec allows ArtifactStore *or* filesystem); `common` is depended on for the shared contract per the global module layout.

**Tech Stack:** Java 17 (Gradle toolchain), Gradle 8.10.2 multi-module (Groovy `build.gradle`), `application` plugin, `io.github.skylot:jadx-core` + `jadx-dex-input` (embedded), picocli, Jackson (in `common`), JUnit 5 + AssertJ, SLF4J simple binding.

## Global Constraints

- **Java 17** — every module uses `java.toolchain.languageVersion = JavaLanguageVersion.of(17)`.
- **Gradle multi-module, Groovy `build.gradle`** — no Kotlin DSL.
- **`application` plugin** for runnable step apps.
- **Test stack:** JUnit 5 and AssertJ versions come from the root `ext` block created by the `common` foundation plan. Tests use `useJUnitPlatform()`.
- **CLI framework:** picocli (`info.picocli:picocli:4.7.6`).
- **JSON:** Jackson comes from the root `jacksonVersion` and is declared in `common`.
- **Decompiler library:** `io.github.skylot:jadx-core:1.5.0` embedded; `io.github.skylot:jadx-dex-input:1.5.0` plugin required to read `.apk`/`.dex`. (jadx CLI is a documented fallback only — not used in code.)
- **Module path:** `apps/decompiler`, Gradle project path `:apps:decompiler`, project name `decompiler`.
- **Shared contracts (in `common`, import don't redefine):** `ArtifactStore { void put(String,byte[]); byte[] get(String); }`, `LocalFsStore(Path root)`.
- **Java package root:** `com.oversecured.sast` (`...common` and `...decompiler`).
- **Test subjects:** `test-subjects/apk/droidbench/` (188 APKs in category subfolders e.g. `GeneralJava/`). Output scratch area: `test-subjects/decompiled/` (leave empty; tests use JUnit `@TempDir`).

### Integration note

The `common` foundation plan owns the canonical root `settings.gradle`, root `build.gradle`, Gradle wrapper version, and shared dependency versions. The root scaffolding snippets below are a standalone bootstrap fallback only. In the full pipeline implementation, do **not** overwrite the root files with this plan's two-module subset; extend the existing all-module root and use `rootProject.ext.*` versions.

---

## File Structure

```
challenge/
├── settings.gradle                 # root: includes common + apps:decompiler   (Task 1)
├── build.gradle                    # root: shared subproject config             (Task 1)
├── gradle.properties               # JVM args                                   (Task 1)
├── gradlew / gradlew.bat / gradle/wrapper/...   # Gradle 8.10.2 wrapper         (Task 1)
├── common/
│   ├── build.gradle                                                             (Task 1)
│   └── src/
│       ├── main/java/com/oversecured/sast/common/
│       │   ├── ArtifactStore.java   # shared interface                          (Task 1)
│       │   └── LocalFsStore.java     # filesystem impl                          (Task 1)
│       └── test/java/com/oversecured/sast/common/
│           └── LocalFsStoreTest.java                                            (Task 1)
└── apps/decompiler/
    ├── build.gradle                  # application + jadx + picocli             (Task 2)
    └── src/
        ├── main/java/com/oversecured/sast/decompiler/
        │   ├── DecompilerException.java   # clear-message failure type          (Task 2)
        │   ├── DecompileResult.java        # record(sourcesDir, manifestFile)   (Task 3)
        │   ├── Decompiler.java             # validate + run jadx                 (Task 2,3)
        │   └── DecompilerCli.java          # picocli wrapper + main             (Task 4)
        └── test/java/com/oversecured/sast/decompiler/
            ├── DecompilerValidationTest.java   # missing/empty/dir APK          (Task 2)
            ├── DecompilerServiceTest.java      # real APK -> sources+manifest   (Task 3)
            ├── DecompilerCliTest.java          # missing APK -> exit !=0        (Task 4)
            └── DecompilerEndToEndTest.java     # full CLI on real APK           (Task 5)
```

---

### Task 1: Bootstrap Gradle multi-module + `common` (ArtifactStore / LocalFsStore)

**Files:**
- Create: `settings.gradle`
- Create: `build.gradle`
- Create: `gradle.properties`
- Create: Gradle 8.10.2 wrapper (`gradlew`, `gradlew.bat`, `gradle/wrapper/gradle-wrapper.jar`, `gradle/wrapper/gradle-wrapper.properties`)
- Create: `common/build.gradle`
- Create: `common/src/main/java/com/oversecured/sast/common/ArtifactStore.java`
- Create: `common/src/main/java/com/oversecured/sast/common/LocalFsStore.java`
- Test: `common/src/test/java/com/oversecured/sast/common/LocalFsStoreTest.java`

**Interfaces:**
- Consumes: nothing (first task).
- Produces:
  - `package com.oversecured.sast.common;`
  - `interface ArtifactStore { void put(String key, byte[] data); byte[] get(String key); }`
  - `class LocalFsStore implements ArtifactStore { LocalFsStore(Path root); }`

- [ ] **Step 1: Create the Gradle wrapper (Gradle 8.10.2)**

If `gradle` is on PATH, run `gradle wrapper --gradle-version 8.10.2 --distribution-type bin` from the repo root. If `gradle` is not installed, install it first (`brew install gradle`) then run the same command. This generates `gradlew`, `gradlew.bat`, `gradle/wrapper/gradle-wrapper.jar`, and `gradle/wrapper/gradle-wrapper.properties`. Verify:

Run: `./gradlew --version`
Expected: prints `Gradle 8.10.2`.

- [ ] **Step 2: Write the root `settings.gradle`**

```groovy
rootProject.name = 'android-taint-sast'

include 'common'
include 'apps:decompiler'
```

- [ ] **Step 3: Write the root `build.gradle` (shared subproject config)**

```groovy
subprojects {
    apply plugin: 'java'

    group = 'com.oversecured.sast'
    version = '0.1.0'

    java {
        toolchain {
            languageVersion = JavaLanguageVersion.of(17)
        }
    }

    repositories {
        mavenCentral()
    }

    dependencies {
        testImplementation "org.junit.jupiter:junit-jupiter:${rootProject.ext.junitVersion}"
        testImplementation "org.assertj:assertj-core:${rootProject.ext.assertjVersion}"
        testRuntimeOnly 'org.junit.platform:junit-platform-launcher'
    }

    tasks.named('test') {
        useJUnitPlatform()
    }
}
```

- [ ] **Step 4: Write `gradle.properties`**

```properties
org.gradle.jvmargs=-Xmx2g
org.gradle.caching=true
```

- [ ] **Step 5: Write `common/build.gradle`**

```groovy
dependencies {
    implementation "com.fasterxml.jackson.core:jackson-databind:${rootProject.ext.jacksonVersion}"
}
```

- [ ] **Step 6: Write the failing test `LocalFsStoreTest.java`**

```java
package com.oversecured.sast.common;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

class LocalFsStoreTest {

    @Test
    void putThenGetRoundTrips(@TempDir Path root) {
        ArtifactStore store = new LocalFsStore(root);
        byte[] payload = "hello-artifact".getBytes(StandardCharsets.UTF_8);

        store.put("nested/dir/file.txt", payload);
        byte[] read = store.get("nested/dir/file.txt");

        assertThat(read).isEqualTo(payload);
    }
}
```

- [ ] **Step 7: Run test to verify it fails**

Run: `./gradlew :common:test --tests 'com.oversecured.sast.common.LocalFsStoreTest'`
Expected: FAIL — compilation error, `ArtifactStore` / `LocalFsStore` do not exist.

- [ ] **Step 8: Write `ArtifactStore.java`**

```java
package com.oversecured.sast.common;

/** Shared artifact contract: every pipeline step reads/writes artifacts by key. */
public interface ArtifactStore {
    void put(String key, byte[] data);

    byte[] get(String key);
}
```

- [ ] **Step 9: Write `LocalFsStore.java`**

```java
package com.oversecured.sast.common;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Filesystem-backed {@link ArtifactStore}; keys are relative paths under {@code root}. */
public final class LocalFsStore implements ArtifactStore {

    private final Path root;

    public LocalFsStore(Path root) {
        this.root = root;
    }

    @Override
    public void put(String key, byte[] data) {
        try {
            Path target = root.resolve(key);
            Path parent = target.getParent();
            Files.createDirectories(parent == null ? root : parent);
            Files.write(target, data);
        } catch (IOException e) {
            throw new UncheckedIOException("failed to write artifact: " + key, e);
        }
    }

    @Override
    public byte[] get(String key) {
        try {
            return Files.readAllBytes(root.resolve(key));
        } catch (IOException e) {
            throw new UncheckedIOException("failed to read artifact: " + key, e);
        }
    }
}
```

- [ ] **Step 10: Run test to verify it passes**

Run: `./gradlew :common:test --tests 'com.oversecured.sast.common.LocalFsStoreTest'`
Expected: PASS.

- [ ] **Step 11: Commit**

```bash
git add settings.gradle build.gradle gradle.properties gradlew gradlew.bat gradle common
git commit -m "feat(common): bootstrap gradle multi-module + ArtifactStore/LocalFsStore"
```

---

### Task 2: `decompiler` module + input validation (`Decompiler.validate`)

**Files:**
- Create: `apps/decompiler/build.gradle`
- Create: `apps/decompiler/src/main/java/com/oversecured/sast/decompiler/DecompilerException.java`
- Create: `apps/decompiler/src/main/java/com/oversecured/sast/decompiler/Decompiler.java`
- Test: `apps/decompiler/src/test/java/com/oversecured/sast/decompiler/DecompilerValidationTest.java`

**Interfaces:**
- Consumes: `com.oversecured.sast.common` (module dependency only; no types used yet).
- Produces:
  - `package com.oversecured.sast.decompiler;`
  - `class DecompilerException extends RuntimeException { DecompilerException(String message); DecompilerException(String message, Throwable cause); }`
  - `class Decompiler { void validate(Path apk); }` — `validate` is package-private, throws `DecompilerException` for null / missing / non-regular-file / empty APK. (Task 3 adds the public `decompile(...)` method to this same class.)

- [ ] **Step 1: Write `apps/decompiler/build.gradle`**

```groovy
plugins {
    id 'application'
}

dependencies {
    implementation project(':common')

    implementation 'io.github.skylot:jadx-core:1.5.0'
    implementation 'io.github.skylot:jadx-dex-input:1.5.0'
    implementation 'info.picocli:picocli:4.7.6'

    // jadx-core logs via SLF4J; provide a concrete binding so it runs cleanly.
    runtimeOnly 'org.slf4j:slf4j-simple:2.0.13'
}

application {
    mainClass = 'com.oversecured.sast.decompiler.DecompilerCli'
}
```

- [ ] **Step 2: Write the failing test `DecompilerValidationTest.java`**

```java
package com.oversecured.sast.decompiler;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DecompilerValidationTest {

    private final Decompiler decompiler = new Decompiler();

    @Test
    void rejectsMissingApk(@TempDir Path tmp) {
        Path missing = tmp.resolve("does-not-exist.apk");

        assertThatThrownBy(() -> decompiler.validate(missing))
                .isInstanceOf(DecompilerException.class)
                .hasMessageContaining("not found");
    }

    @Test
    void rejectsEmptyApk(@TempDir Path tmp) throws IOException {
        Path empty = Files.createFile(tmp.resolve("empty.apk"));

        assertThatThrownBy(() -> decompiler.validate(empty))
                .isInstanceOf(DecompilerException.class)
                .hasMessageContaining("empty");
    }

    @Test
    void rejectsDirectoryAsApk(@TempDir Path tmp) throws IOException {
        Path dir = Files.createDirectory(tmp.resolve("dir.apk"));

        assertThatThrownBy(() -> decompiler.validate(dir))
                .isInstanceOf(DecompilerException.class)
                .hasMessageContaining("not a regular file");
    }

    @Test
    void acceptsNonEmptyRegularFile(@TempDir Path tmp) throws IOException {
        Path ok = Files.write(tmp.resolve("ok.apk"), new byte[]{1, 2, 3});

        // Should not throw.
        decompiler.validate(ok);
        assertThat(Files.exists(ok)).isTrue();
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `./gradlew :apps:decompiler:test --tests 'com.oversecured.sast.decompiler.DecompilerValidationTest'`
Expected: FAIL — `Decompiler` and `DecompilerException` do not exist (compilation error).

- [ ] **Step 4: Write `DecompilerException.java`**

```java
package com.oversecured.sast.decompiler;

/** Thrown when decompilation cannot proceed; carries a human-readable message for the CLI. */
public class DecompilerException extends RuntimeException {

    public DecompilerException(String message) {
        super(message);
    }

    public DecompilerException(String message, Throwable cause) {
        super(message, cause);
    }
}
```

- [ ] **Step 5: Write `Decompiler.java` (validation only for now)**

```java
package com.oversecured.sast.decompiler;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Decompiles an APK into a Java source tree + decoded AndroidManifest.xml using embedded jadx. */
public final class Decompiler {

    /**
     * Validates that {@code apk} is a readable, non-empty regular file.
     *
     * @throws DecompilerException with a clear message otherwise.
     */
    void validate(Path apk) {
        if (apk == null) {
            throw new DecompilerException("apk path is null");
        }
        if (!Files.exists(apk)) {
            throw new DecompilerException("apk not found: " + apk);
        }
        if (!Files.isRegularFile(apk)) {
            throw new DecompilerException("apk is not a regular file: " + apk);
        }
        try {
            if (Files.size(apk) == 0) {
                throw new DecompilerException("apk is empty: " + apk);
            }
        } catch (IOException e) {
            throw new DecompilerException("cannot read apk: " + apk + " (" + e.getMessage() + ")", e);
        }
    }
}
```

- [ ] **Step 6: Run test to verify it passes**

Run: `./gradlew :apps:decompiler:test --tests 'com.oversecured.sast.decompiler.DecompilerValidationTest'`
Expected: PASS (4 tests).

- [ ] **Step 7: Commit**

```bash
git add apps/decompiler
git commit -m "feat(decompiler): module setup + APK input validation"
```

---

### Task 3: `Decompiler.decompile` — run jadx, produce sources + manifest

**Files:**
- Create: `apps/decompiler/src/main/java/com/oversecured/sast/decompiler/DecompileResult.java`
- Modify: `apps/decompiler/src/main/java/com/oversecured/sast/decompiler/Decompiler.java`
- Test: `apps/decompiler/src/test/java/com/oversecured/sast/decompiler/DecompilerServiceTest.java`

**Interfaces:**
- Consumes: `Decompiler.validate(Path)` and `DecompilerException` (Task 2).
- Produces:
  - `record DecompileResult(Path sourcesDir, Path manifestFile) {}`
  - `DecompileResult Decompiler.decompile(Path apk, Path outDir)` — validates, runs jadx writing the `.java` tree and decoded `AndroidManifest.xml` into `outDir`, returns `new DecompileResult(outDir, outDir.resolve("AndroidManifest.xml"))`. Throws `DecompilerException` if jadx fails or produces no `.java` files.

- [ ] **Step 1: Write the failing test `DecompilerServiceTest.java`**

The test locates the first APK in `GeneralJava/` at runtime (do not hardcode a filename), decompiles into a `@TempDir`, and asserts a `.java` file and the manifest were produced.

```java
package com.oversecured.sast.decompiler;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class DecompilerServiceTest {

    /** Resolve the repo root from the module's working dir (Gradle runs tests in apps/decompiler). */
    private static Path repoRoot() {
        return Path.of("").toAbsolutePath().getParent().getParent();
    }

    private static Path firstGeneralJavaApk() throws IOException {
        Path dir = repoRoot().resolve("test-subjects/apk/droidbench/GeneralJava");
        try (Stream<Path> s = Files.list(dir)) {
            return s.filter(p -> p.toString().endsWith(".apk"))
                    .sorted(Comparator.naturalOrder())
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException("no .apk in " + dir));
        }
    }

    @Test
    void decompilesRealApkToSourcesAndManifest(@TempDir Path out) throws IOException {
        Path apk = firstGeneralJavaApk();

        DecompileResult result = new Decompiler().decompile(apk, out);

        assertThat(result.sourcesDir()).isEqualTo(out);
        assertThat(result.manifestFile()).exists();

        boolean hasJava;
        try (Stream<Path> s = Files.walk(out)) {
            hasJava = s.anyMatch(p -> p.toString().endsWith(".java"));
        }
        assertThat(hasJava).as("at least one .java file produced").isTrue();
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :apps:decompiler:test --tests 'com.oversecured.sast.decompiler.DecompilerServiceTest'`
Expected: FAIL — `DecompileResult` and `Decompiler.decompile(...)` do not exist (compilation error).

- [ ] **Step 3: Write `DecompileResult.java`**

```java
package com.oversecured.sast.decompiler;

import java.nio.file.Path;

/** Output locations of a decompile run. */
public record DecompileResult(Path sourcesDir, Path manifestFile) {
}
```

- [ ] **Step 4: Add `decompile(...)` to `Decompiler.java`**

Add the imports and the public method to the existing class (keep `validate` from Task 2).

```java
package com.oversecured.sast.decompiler;

import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

/** Decompiles an APK into a Java source tree + decoded AndroidManifest.xml using embedded jadx. */
public final class Decompiler {

    /**
     * Decompiles {@code apk} into {@code outDir}: jadx writes the .java package tree and the
     * decoded AndroidManifest.xml directly into {@code outDir} (the CLI's --out is the sources dir).
     *
     * @throws DecompilerException on bad input, jadx failure, or when no .java sources are produced.
     */
    public DecompileResult decompile(Path apk, Path outDir) {
        validate(apk);

        try {
            Files.createDirectories(outDir);
        } catch (IOException e) {
            throw new DecompilerException("cannot create output dir: " + outDir + " (" + e.getMessage() + ")", e);
        }

        JadxArgs args = new JadxArgs();
        args.setInputFiles(List.of(apk.toFile()));
        // --out is the output dir itself: emit sources AND resources (incl. manifest) into it.
        args.setOutDir(outDir.toFile());
        args.setOutDirSrc(outDir.toFile());
        args.setOutDirRes(outDir.toFile());

        try (JadxDecompiler jadx = new JadxDecompiler(args)) {
            jadx.load();
            jadx.save();
        } catch (RuntimeException e) {
            throw new DecompilerException("jadx failed to decompile: " + apk + " (" + e.getMessage() + ")", e);
        }

        if (!hasJavaFile(outDir)) {
            throw new DecompilerException(
                    "decompilation produced no .java sources for: " + apk + " (corrupt or unsupported APK?)");
        }

        return new DecompileResult(outDir, outDir.resolve("AndroidManifest.xml"));
    }

    void validate(Path apk) {
        if (apk == null) {
            throw new DecompilerException("apk path is null");
        }
        if (!Files.exists(apk)) {
            throw new DecompilerException("apk not found: " + apk);
        }
        if (!Files.isRegularFile(apk)) {
            throw new DecompilerException("apk is not a regular file: " + apk);
        }
        try {
            if (Files.size(apk) == 0) {
                throw new DecompilerException("apk is empty: " + apk);
            }
        } catch (IOException e) {
            throw new DecompilerException("cannot read apk: " + apk + " (" + e.getMessage() + ")", e);
        }
    }

    private static boolean hasJavaFile(Path dir) {
        try (Stream<Path> s = Files.walk(dir)) {
            return s.anyMatch(p -> p.toString().endsWith(".java"));
        } catch (IOException e) {
            return false;
        }
    }
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `./gradlew :apps:decompiler:test --tests 'com.oversecured.sast.decompiler.DecompilerServiceTest'`
Expected: PASS. (First run downloads jadx artifacts; allow a longer timeout.)

- [ ] **Step 6: Commit**

```bash
git add apps/decompiler
git commit -m "feat(decompiler): jadx-backed decompile to sources + manifest"
```

---

### Task 4: `DecompilerCli` — picocli wrapper + exit codes

**Files:**
- Create: `apps/decompiler/src/main/java/com/oversecured/sast/decompiler/DecompilerCli.java`
- Test: `apps/decompiler/src/test/java/com/oversecured/sast/decompiler/DecompilerCliTest.java`

**Interfaces:**
- Consumes: `Decompiler.decompile(Path, Path)`, `DecompileResult`, `DecompilerException` (Task 3).
- Produces:
  - `class DecompilerCli implements Callable<Integer>` — picocli `@Command(name = "decompile")` with required `--apk` and `--out` options (both `Path`). `call()` returns `0` on success, `1` on `DecompilerException` (message printed to `System.err`). `static void main(String[])` calls `System.exit(new CommandLine(new DecompilerCli()).execute(args))`.

- [ ] **Step 1: Write the failing test `DecompilerCliTest.java`**

```java
package com.oversecured.sast.decompiler;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

class DecompilerCliTest {

    @Test
    void missingApkExitsNonZeroWithClearError(@TempDir Path tmp) {
        Path missing = tmp.resolve("nope.apk");
        Path out = tmp.resolve("out");

        StringWriter err = new StringWriter();
        CommandLine cmd = new CommandLine(new DecompilerCli());
        cmd.setErr(new PrintWriter(err));

        int exit = cmd.execute("--apk", missing.toString(), "--out", out.toString());

        assertThat(exit).isNotZero();
        assertThat(err.toString()).contains("decompile failed").contains("not found");
    }

    @Test
    void missingRequiredOptionExitsNonZero(@TempDir Path tmp) {
        CommandLine cmd = new CommandLine(new DecompilerCli());
        cmd.setErr(new PrintWriter(new StringWriter()));

        int exit = cmd.execute("--out", tmp.toString()); // no --apk

        assertThat(exit).isNotZero();
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :apps:decompiler:test --tests 'com.oversecured.sast.decompiler.DecompilerCliTest'`
Expected: FAIL — `DecompilerCli` does not exist (compilation error).

- [ ] **Step 3: Write `DecompilerCli.java`**

```java
package com.oversecured.sast.decompiler;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.nio.file.Path;
import java.util.concurrent.Callable;

@Command(
        name = "decompile",
        mixinStandardHelpOptions = true,
        description = "Decompile an Android APK into a .java source tree + decoded AndroidManifest.xml.")
public final class DecompilerCli implements Callable<Integer> {

    @Option(names = "--apk", required = true, description = "Path to the input APK.")
    Path apk;

    @Option(names = "--out", required = true, description = "Output directory for sources + manifest.")
    Path out;

    private final Decompiler decompiler = new Decompiler();

    @Override
    public Integer call() {
        try {
            DecompileResult result = decompiler.decompile(apk, out);
            System.out.println("decompiled " + apk + " -> " + result.sourcesDir());
            return 0;
        } catch (DecompilerException e) {
            System.err.println("decompile failed: " + e.getMessage());
            return 1;
        }
    }

    public static void main(String[] args) {
        System.exit(new CommandLine(new DecompilerCli()).execute(args));
    }
}
```

Note: the test injects an error writer via `cmd.setErr(...)`; `call()` also prints to `System.err` for production use. Both the `--apk`-missing path (our `return 1` + `System.err` message) and the missing-required-option path (picocli's own usage error → non-zero) are covered.

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :apps:decompiler:test --tests 'com.oversecured.sast.decompiler.DecompilerCliTest'`
Expected: PASS (2 tests). The `not found` assertion confirms the clear error message flows from `Decompiler.validate` through the CLI.

- [ ] **Step 5: Commit**

```bash
git add apps/decompiler
git commit -m "feat(decompiler): picocli CLI wrapper with non-zero exit on failure"
```

---

### Task 5: END-TO-END TEST — full CLI on a real DroidBench APK

**Files:**
- Test: `apps/decompiler/src/test/java/com/oversecured/sast/decompiler/DecompilerEndToEndTest.java`

**Interfaces:**
- Consumes: `DecompilerCli` via `picocli.CommandLine.execute(...)` (Task 4) — exercises the entire path (CLI → service → jadx → filesystem).
- Produces: nothing (verification only).

Before writing the test, list the available APKs so the chosen subject is real:

Run: `ls test-subjects/apk/droidbench/GeneralJava/`
Expected: a list of `.apk` files (e.g. `Clone1.apk`, `Exceptions1.apk`, ...). The test selects the **first** `.apk` (sorted) at runtime — do not hardcode a name.

- [ ] **Step 1: Write the end-to-end test**

```java
package com.oversecured.sast.decompiler;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class DecompilerEndToEndTest {

    private static Path repoRoot() {
        return Path.of("").toAbsolutePath().getParent().getParent();
    }

    private static Path firstGeneralJavaApk() throws IOException {
        Path dir = repoRoot().resolve("test-subjects/apk/droidbench/GeneralJava");
        try (Stream<Path> s = Files.list(dir)) {
            return s.filter(p -> p.toString().endsWith(".apk"))
                    .sorted(Comparator.naturalOrder())
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException("no .apk in " + dir));
        }
    }

    @Test
    void cliDecompilesApkProducingJavaAndManifest(@TempDir Path out) throws IOException {
        Path apk = firstGeneralJavaApk();

        int exit = new CommandLine(new DecompilerCli())
                .execute("--apk", apk.toString(), "--out", out.toString());
        assertThat(exit).isZero();

        // 1) at least one .java file under the output
        boolean hasJava;
        try (Stream<Path> s = Files.walk(out)) {
            hasJava = s.anyMatch(p -> p.toString().endsWith(".java"));
        }
        assertThat(hasJava).as("at least one .java file under output").isTrue();

        // 2) AndroidManifest.xml exists under the output and contains "<manifest"
        Path manifest;
        try (Stream<Path> s = Files.walk(out)) {
            manifest = s.filter(p -> p.getFileName().toString().equals("AndroidManifest.xml"))
                    .findFirst()
                    .orElseThrow(() -> new AssertionError("no AndroidManifest.xml under " + out));
        }
        String xml = Files.readString(manifest, StandardCharsets.UTF_8);
        assertThat(xml).contains("<manifest");
    }
}
```

- [ ] **Step 2: Run the end-to-end test to verify it passes**

Run: `./gradlew :apps:decompiler:test --tests 'com.oversecured.sast.decompiler.DecompilerEndToEndTest'`
Expected: PASS. Asserts exit code 0, a decompiled `.java` file exists, and a decoded `AndroidManifest.xml` containing `<manifest` exists under the output.

- [ ] **Step 3: Run the full module test suite (regression check)**

Run: `./gradlew :apps:decompiler:test`
Expected: PASS — all of `DecompilerValidationTest`, `DecompilerServiceTest`, `DecompilerCliTest`, `DecompilerEndToEndTest`.

- [ ] **Step 4: Run the full build to confirm the executable assembles**

Run: `./gradlew build`
Expected: BUILD SUCCESSFUL; `apps/decompiler` produces its `installDist`/run scripts via the `application` plugin.

- [ ] **Step 5: Commit**

```bash
git add apps/decompiler
git commit -m "test(decompiler): end-to-end CLI decompile of a real DroidBench APK"
```

---

## Self-Review (plan vs spec)

**1. Spec coverage (for step 1 / `apps/decompiler` only — other steps are out of scope of this plan):**
- Spec §3.1 step 1 `decompile --apk a.apk --out sources/` → Tasks 3–4 (CLI options + service; `--out` treated as the sources dir per the spec's own CLI example). ✓
- Module README "APK → `.java` + extracts raw `AndroidManifest.xml`" → Task 3 (`setOutDirSrc`/`setOutDirRes` = `outDir`; manifest decoded into the same dir; jadx `jadx-dex-input` plugin added so dex/apk is readable). ✓
- Module README test "tiny fixture APK → expected `.java` files and a decoded manifest exist" → Task 3 + Task 5 (real DroidBench `GeneralJava` APK). ✓
- Module README test "corrupt/empty APK → graceful, non-zero exit with clear error" → Task 2 (empty/missing/dir validation) + Task 3 (no-`.java`-produced guard) + Task 4 (CLI exit 1 + stderr message). ✓
- Spec §2 / README "jadx-core embedded, jadx CLI documented fallback" → embedded `jadx-core` + `jadx-dex-input` used; CLI fallback noted in Global Constraints, not coded. ✓
- Shared contract "import don't redefine `ArtifactStore`/`LocalFsStore`" → defined once in `common` (Task 1); decompiler depends on `:common`. ✓
- Required END-TO-END test (real APK → JUnit `@TempDir`, assert ≥1 `.java` + `AndroidManifest.xml` contains `<manifest`) → Task 5. ✓
- Required unit test (missing apk → non-zero exit + clear error) → Task 4 `missingApkExitsNonZeroWithClearError`. ✓
- Tech stack pins (Java 17, Gradle Groovy multi-module, `application`, JUnit5+AssertJ, picocli, Jackson) → Global Constraints + Tasks 1–2. ✓

**2. Placeholder scan:** No `TBD`/`TODO`/"handle edge cases"/"similar to Task N". Every code step shows complete, compilable code; every run step shows an exact `./gradlew` command and expected PASS/FAIL. ✓

**3. Type consistency:** `ArtifactStore.put(String,byte[])`/`get(String)` and `LocalFsStore(Path)` match the shared contract verbatim. `Decompiler.validate(Path)` (Task 2) is reused unchanged inside `decompile(Path,Path)` (Task 3). `DecompileResult(Path sourcesDir, Path manifestFile)` is used identically in `Decompiler`, `DecompilerCli`, and both service/E2E tests. `DecompilerException(String)`/`(String,Throwable)` signatures are consistent across all throw sites. CLI option fields `apk`/`out` (`Path`) align with `decompile(Path,Path)`. ✓

**Known discrepancy (intentional):** The module README phrases the manifest output as `sources/AndroidManifest.xml` while spec §3.1 lists `sources/ + AndroidManifest.xml`. This plan follows the spec's CLI example (`--out sources/`), so `--out` *is* the sources directory and the manifest lands at `<out>/AndroidManifest.xml` — satisfying both readings (manifest sits inside the sources dir). Downstream `manifest-facts` (step 3, separate plan) reads `<sources>/AndroidManifest.xml`, which this produces. The E2E test searches recursively, so it is robust to either layout if a future jadx version nests resources.

---

## Execution Handoff

Plan complete. Two execution options:
1. **Subagent-Driven (recommended)** — fresh subagent per task + review between tasks.
2. **Inline Execution** — execute tasks in this session with checkpoints.
