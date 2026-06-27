package com.oversecured.sast.taint.icc;

import static org.assertj.core.api.Assertions.assertThat;

import com.oversecured.sast.common.ComponentFact;
import com.oversecured.sast.common.ManifestFacts;
import com.oversecured.sast.common.Severity;
import com.oversecured.sast.parser.AstIndex;
import com.oversecured.sast.taint.TaintAnalyzer;
import com.oversecured.sast.taint.model.ManifestConditions;
import com.oversecured.sast.taint.model.Rule;
import com.oversecured.sast.taint.model.SinkSpec;
import com.oversecured.sast.taint.model.SourceSpec;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class IccModelTest {
    @Test
    void taintedPutExtraBecomesGetStringExtraSourceInTargetActivity() {
        AstIndex index = AstIndex.build(Path.of("src/test/resources/fixtures/taint-src/icc"));
        ManifestFacts facts = new ManifestFacts("com.example", List.of(
                new ComponentFact("com.example.DeeplinkActivity", "activity", true, List.of(), false, null),
                new ComponentFact("com.example.WebViewActivity", "activity", false, List.of(), false, null)), List.of());
        Rule rule = new Rule("R", "webview-open-redirect", Severity.ERROR, "CWE-601", "M1", "msg",
                new ManifestConditions(true),
                List.of(new SourceSpec("com.example.Intent: java.lang.String getStringExtra(java.lang.String)")),
                List.of(new SinkSpec("com.example.WebView: void loadUrl(java.lang.String)", List.of(0))),
                List.of(), List.of());

        var doc = new TaintAnalyzer().analyze(index, facts, rule);

        assertThat(doc.findings()).hasSize(1);
        assertThat(doc.findings().get(0).flow()).extracting(step -> step.label())
                .anySatisfy(label -> assertThat(label).contains("putExtra(\"url\")"))
                .anySatisfy(label -> assertThat(label).contains("getStringExtra(\"url\")"));
    }
}
