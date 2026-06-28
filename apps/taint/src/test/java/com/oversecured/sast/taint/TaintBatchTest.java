package com.oversecured.sast.taint;

import static org.assertj.core.api.Assertions.assertThat;

import com.oversecured.sast.common.FindingsDoc;
import com.oversecured.sast.common.Json;
import com.oversecured.sast.parser.AstIndex;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class TaintBatchTest {
    @TempDir
    Path temp;

    private Path facts() throws Exception {
        Path facts = temp.resolve("facts.json");
        Files.writeString(facts, """
                {
                  "packageName": "com.example",
                  "components": [
                    {"name":"com.example.BasicFlows","type":"activity","exported":true,"intentFilters":[],"permission":null}
                  ],
                  "permissions": []
                }
                """);
        return facts;
    }

    @Test
    void runBatchWritesOneFindingsFilePerRuleFromSingleLoad() throws Exception {
        AstIndex index = AstIndex.build(Path.of("src/test/resources/fixtures/taint-src/basic"));
        Path astDir = temp.resolve("ast-index");
        index.save(astDir);
        Path facts = facts();

        Path webviewOut = temp.resolve("findings-webview.json");
        Path pathOut = temp.resolve("findings-path.json");

        new TaintAnalyzer().runBatch(astDir, facts, List.of(
                new TaintAnalyzer.RuleRun(Path.of("src/test/resources/fixtures/rules/webview-mini.yaml"), webviewOut),
                new TaintAnalyzer.RuleRun(Path.of("src/test/resources/fixtures/rules/pathtraversal-mini.yaml"), pathOut)));

        FindingsDoc webview = Json.read(Files.readAllBytes(webviewOut), FindingsDoc.class);
        assertThat(webview.findings()).hasSizeGreaterThanOrEqualTo(1);
        assertThat(webview.findings().get(0).ruleId()).isEqualTo("ANDROID_WEBVIEW_INTENT_LOADURL");

        // Each rule gets its own independent findings file (path-traversal rule finds nothing in basic).
        FindingsDoc path = Json.read(Files.readAllBytes(pathOut), FindingsDoc.class);
        assertThat(path.analyzer()).isEqualTo("taint-engine");
        assertThat(path.findings()).isEmpty();
    }

    @Test
    void runBatchMatchesIndividualRun() throws Exception {
        AstIndex index = AstIndex.build(Path.of("src/test/resources/fixtures/taint-src/basic"));
        Path astDir = temp.resolve("ast-index");
        index.save(astDir);
        Path facts = facts();
        Path rule = Path.of("src/test/resources/fixtures/rules/webview-mini.yaml");

        Path single = temp.resolve("single.json");
        new TaintAnalyzer().run(astDir, facts, rule, single);

        Path batch = temp.resolve("batch.json");
        new TaintAnalyzer().runBatch(astDir, facts, List.of(new TaintAnalyzer.RuleRun(rule, batch)));

        assertThat(Files.readString(batch)).isEqualTo(Files.readString(single));
    }
}
