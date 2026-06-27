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
