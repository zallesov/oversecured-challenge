package com.oversecured.sast.taint.cli;

import static org.assertj.core.api.Assertions.assertThat;

import com.oversecured.sast.common.FindingsDoc;
import com.oversecured.sast.common.Json;
import com.oversecured.sast.parser.AstIndex;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

class TaintCommandTest {
    @TempDir
    Path temp;

    @Test
    void cliAcceptsAstFactsRuleAndOutOptions() throws Exception {
        Path ast = temp.resolve("ast-index");
        AstIndex.build(Path.of("src/test/resources/fixtures/taint-src/basic")).save(ast);
        Path facts = temp.resolve("facts.json");
        Files.writeString(facts, """
                {"packageName":"com.example","components":[
                  {"name":"com.example.BasicFlows","type":"activity","exported":true,"intentFilters":[],"permission":null}
                ],"permissions":[]}
                """);
        Path out = temp.resolve("findings.json");

        int exit = new CommandLine(new TaintCommand()).execute(
                "--ast", ast.toString(),
                "--facts", facts.toString(),
                "--rule", "src/test/resources/fixtures/rules/webview-mini.yaml",
                "--out", out.toString());

        assertThat(exit).isEqualTo(0);
        assertThat(out).exists();
        assertThat(Json.read(Files.readAllBytes(out), FindingsDoc.class).analyzer()).isEqualTo("taint-engine");
    }
}
