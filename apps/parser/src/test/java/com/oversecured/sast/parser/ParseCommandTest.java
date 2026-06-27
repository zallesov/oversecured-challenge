package com.oversecured.sast.parser;

import static org.assertj.core.api.Assertions.assertThat;

import com.oversecured.sast.parser.cli.ParseCommand;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ParseCommandTest {

    @Test
    void parseCliWritesAstIndexArtifact(@TempDir Path out) {
        Path src = Paths.get("src", "test", "resources", "fixtures", "simple");

        int code = ParseCommand.run("--src", src.toString(), "--out", out.toString());

        assertThat(code).isZero();
        assertThat(Files.exists(out.resolve("index-meta.json"))).isTrue();
        // The artifact reloads into a usable index.
        assertThat(AstIndex.load(out).units()).hasSize(2);
    }

    @Test
    void parseCliFailsWhenSrcMissing(@TempDir Path out) {
        int code = ParseCommand.run("--out", out.toString());
        assertThat(code).isNotZero(); // picocli reports missing required --src
    }
}
