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
