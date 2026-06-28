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

    // LangChain4j's ToolExecutionResultMessage rejects blank text (ensureNotBlank), so a tool that
    // returns "" aborts the whole agent loop. Every tool result must be non-blank.

    @Test
    void searchCodeWithNoMatchesIsNotBlank(@TempDir Path root) throws Exception {
        Files.writeString(root.resolve("A.java"), "class A {}\n");
        SourceTools tools = new SourceTools(root);

        assertThat(tools.searchCode("nothingHere").isBlank()).isFalse();
    }

    @Test
    void listDirOnEmptyDirIsNotBlank(@TempDir Path root) throws Exception {
        Files.createDirectories(root.resolve("empty"));
        SourceTools tools = new SourceTools(root);

        assertThat(tools.listDir("empty").isBlank()).isFalse();
    }

    @Test
    void readFileWithEmptyRangeIsNotBlank(@TempDir Path root) throws Exception {
        Files.writeString(root.resolve("A.java"), "l1\nl2\n");
        SourceTools tools = new SourceTools(root);

        // start beyond end-of-file yields no lines; must still be non-blank.
        assertThat(tools.readFile("A.java", 5, 9).isBlank()).isFalse();
    }
}
