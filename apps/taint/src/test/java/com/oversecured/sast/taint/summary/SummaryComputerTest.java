package com.oversecured.sast.taint.summary;

import static org.assertj.core.api.Assertions.assertThat;

import com.github.javaparser.ast.body.MethodDeclaration;
import com.oversecured.sast.common.Severity;
import com.oversecured.sast.parser.AstIndex;
import com.oversecured.sast.taint.flow.IntraProceduralAnalyzer;
import com.oversecured.sast.taint.match.RuleMatcher;
import com.oversecured.sast.taint.model.ManifestConditions;
import com.oversecured.sast.taint.model.Rule;
import com.oversecured.sast.taint.model.SinkSpec;
import com.oversecured.sast.taint.model.SourceSpec;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class SummaryComputerTest {
    private static Rule rule() {
        return new Rule("R", "webview-open-redirect", Severity.ERROR, "CWE-601", "M1", "msg",
                new ManifestConditions(false),
                List.of(new SourceSpec("com.example.Intent: java.lang.String getStringExtra(java.lang.String)")),
                List.of(new SinkSpec("com.example.WebView: void loadUrl(java.lang.String)", List.of(0))),
                List.of(), List.of());
    }

    private static MethodDeclaration method(AstIndex index, String name) {
        return index.units().stream()
                .flatMap(cu -> cu.findAll(MethodDeclaration.class).stream())
                .filter(m -> m.getNameAsString().equals(name))
                .findFirst().orElseThrow();
    }

    @Test
    void summaryCarriesTaintThroughHelperReturnOnlyWhenHelperReturnsParam() {
        AstIndex index = AstIndex.build(Path.of("src/test/resources/fixtures/taint-src/summary"));
        RuleMatcher matcher = RuleMatcher.forRule(rule());
        List<MethodSummary> summaries = new SummaryComputer(index, matcher, rule()).compute();

        assertThat(new IntraProceduralAnalyzer(index, matcher, rule(), summaries)
                .analyzeMethod(method(index, "throughHelper"))).hasSize(1);
        assertThat(new IntraProceduralAnalyzer(index, matcher, rule(), summaries)
                .analyzeMethod(method(index, "throughCleanHelper"))).isEmpty();
    }
}
