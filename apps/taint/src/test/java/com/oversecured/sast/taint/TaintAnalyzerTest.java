package com.oversecured.sast.taint;

import static org.assertj.core.api.Assertions.assertThat;

import com.oversecured.sast.common.FindingsDoc;
import com.oversecured.sast.common.Json;
import com.oversecured.sast.parser.AstIndex;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class TaintAnalyzerTest {
    @TempDir
    Path temp;

    @Test
    void runWritesSharedFindingsDocJson() throws Exception {
        AstIndex index = AstIndex.build(Path.of("src/test/resources/fixtures/taint-src/basic"));
        Path astDir = temp.resolve("ast-index");
        index.save(astDir);

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

        Path out = temp.resolve("findings.json");
        new TaintAnalyzer().run(astDir, facts, Path.of("src/test/resources/fixtures/rules/webview-mini.yaml"), out);

        FindingsDoc doc = Json.read(Files.readAllBytes(out), FindingsDoc.class);
        assertThat(doc.analyzer()).isEqualTo("taint-engine");
        assertThat(doc.findings()).hasSizeGreaterThanOrEqualTo(1);
        assertThat(doc.findings().get(0).ruleId()).isEqualTo("ANDROID_WEBVIEW_INTENT_LOADURL");
        assertThat(doc.findings().get(0).vulnerabilityClass()).isEqualTo("webview-open-redirect");
    }
}
