package com.oversecured.sast.taint.flow;

import static org.assertj.core.api.Assertions.assertThat;

import com.github.javaparser.ast.body.MethodDeclaration;
import com.oversecured.sast.common.Severity;
import com.oversecured.sast.parser.AstIndex;
import com.oversecured.sast.taint.match.RuleMatcher;
import com.oversecured.sast.taint.model.ManifestConditions;
import com.oversecured.sast.taint.model.Rule;
import com.oversecured.sast.taint.model.SanitizerSpec;
import com.oversecured.sast.taint.model.SinkSpec;
import com.oversecured.sast.taint.model.SourceSpec;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class IntraProceduralAnalyzerTest {
    private static Rule basicRule() {
        return new Rule(
                "R", "webview-open-redirect", Severity.ERROR, "CWE-601", "M1", "msg",
                new ManifestConditions(false),
                List.of(new SourceSpec("android.content.Intent: java.lang.String getStringExtra(java.lang.String)")),
                List.of(new SinkSpec("android.webkit.WebView: void loadUrl(java.lang.String)", List.of(0))),
                List.of(),
                List.of("java.lang.String: java.lang.String concat(java.lang.String)"));
    }

    private static MethodDeclaration method(AstIndex index, String name) {
        return index.units().stream()
                .flatMap(cu -> cu.findAll(MethodDeclaration.class).stream())
                .filter(m -> m.getNameAsString().equals(name))
                .findFirst().orElseThrow();
    }

    @Test
    void reportsDirectSourceToSink() {
        AstIndex index = AstIndex.build(Path.of("src/test/resources/fixtures/taint-src/basic"));
        var findings = new IntraProceduralAnalyzer(index, RuleMatcher.forRule(basicRule()), basicRule(), List.of())
                .analyzeMethod(method(index, "direct"));

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).flow()).extracting(step -> step.label())
                .anySatisfy(label -> assertThat(label).contains("source"))
                .anySatisfy(label -> assertThat(label).contains("sink"));
    }

    @Test
    void reassignmentToCleanValueKillsTaint() {
        AstIndex index = AstIndex.build(Path.of("src/test/resources/fixtures/taint-src/basic"));
        var findings = new IntraProceduralAnalyzer(index, RuleMatcher.forRule(basicRule()), basicRule(), List.of())
                .analyzeMethod(method(index, "killed"));

        assertThat(findings).isEmpty();
    }

    @Test
    void propagatorCarriesTaintToAssignedValue() {
        AstIndex index = AstIndex.build(Path.of("src/test/resources/fixtures/taint-src/basic"));
        var findings = new IntraProceduralAnalyzer(index, RuleMatcher.forRule(basicRule()), basicRule(), List.of())
                .analyzeMethod(method(index, "propagated"));

        assertThat(findings).hasSize(1);
    }

    @Test
    void fullSanitizerKillsTaintInsideGuardedBlock() {
        AstIndex index = AstIndex.build(Path.of("src/test/resources/fixtures/taint-src/basic"));
        Rule rule = new Rule(
                "R", "webview-open-redirect", Severity.ERROR, "CWE-601", "M1", "msg",
                new ManifestConditions(false),
                List.of(new SourceSpec("android.content.Intent: java.lang.String getStringExtra(java.lang.String)")),
                List.of(new SinkSpec("android.webkit.WebView: void loadUrl(java.lang.String)", List.of(0))),
                List.of(new SanitizerSpec("android.webkit.URLUtil: boolean isHttpsUrl(java.lang.String)")),
                List.of());

        var findings = new IntraProceduralAnalyzer(index, RuleMatcher.forRule(rule), rule, List.of())
                .analyzeMethod(method(index, "sanitized"));

        assertThat(findings).isEmpty();
    }

    @Test
    void incompleteEndsWithSanitizerStillReportsWithNote() {
        AstIndex index = AstIndex.build(Path.of("src/test/resources/fixtures/taint-src/basic"));
        var findings = new IntraProceduralAnalyzer(index, RuleMatcher.forRule(basicRule()), basicRule(), List.of())
                .analyzeMethod(method(index, "incompleteSanitized"));

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).notes())
                .anySatisfy(note -> assertThat(note).startsWith("incomplete-sanitizer:"));
    }
}
