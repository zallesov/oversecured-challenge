package com.oversecured.sast.taint;

import static org.assertj.core.api.Assertions.assertThat;

import com.oversecured.sast.common.FindingsDoc;
import com.oversecured.sast.common.Json;
import com.oversecured.sast.parser.AstIndex;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class TaintEndToEndTest {
    @TempDir
    Path temp;

    @Test
    void webviewFixtureProducesExactlyOneFinding() throws Exception {
        Path ast = temp.resolve("webview-ast");
        AstIndex.build(Path.of("src/test/resources/fixtures/taint-src/webview-e2e")).save(ast);
        Path out = temp.resolve("webview-findings.json");

        new TaintAnalyzer().run(ast,
                Path.of("src/test/resources/fixtures/facts/webview-exported.json"),
                Path.of("src/test/resources/fixtures/rules/webview-mini.yaml"),
                out);

        FindingsDoc doc = Json.read(Files.readAllBytes(out), FindingsDoc.class);
        assertThat(doc.findings()).hasSize(1);
        assertThat(doc.findings().get(0).ruleId()).isEqualTo("ANDROID_WEBVIEW_INTENT_LOADURL");
    }

    @Test
    void pathTraversalFixtureProducesExactlyOneFinding() throws Exception {
        Path ast = temp.resolve("pathtrav-ast");
        AstIndex.build(Path.of("src/test/resources/fixtures/taint-src/pathtrav")).save(ast);
        Path out = temp.resolve("pathtrav-findings.json");

        new TaintAnalyzer().run(ast,
                Path.of("src/test/resources/fixtures/facts/pathtrav-exported.json"),
                Path.of("src/test/resources/fixtures/rules/pathtraversal-mini.yaml"),
                out);

        FindingsDoc doc = Json.read(Files.readAllBytes(out), FindingsDoc.class);
        assertThat(doc.findings()).hasSize(1);
        assertThat(doc.findings().get(0).ruleId()).isEqualTo("ANDROID_PATH_TRAVERSAL_PROVIDER");
    }
}
