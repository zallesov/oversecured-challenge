package com.oversecured.sast.taint.match;

import static org.assertj.core.api.Assertions.assertThat;

import com.oversecured.sast.common.Severity;
import com.oversecured.sast.taint.model.ManifestConditions;
import com.oversecured.sast.taint.model.Rule;
import com.oversecured.sast.taint.model.SanitizerSpec;
import com.oversecured.sast.taint.model.SinkSpec;
import com.oversecured.sast.taint.model.SourceSpec;
import java.util.List;
import org.junit.jupiter.api.Test;

class RuleMatcherTest {
    @Test
    void matchesBareRuleSignaturesAgainstBracketedResolvedCalls() {
        Rule rule = new Rule(
                "R", "webview-open-redirect", Severity.ERROR, "CWE-601", "M1", "msg",
                new ManifestConditions(true),
                List.of(new SourceSpec("android.content.Intent: java.lang.String getStringExtra(java.lang.String)")),
                List.of(new SinkSpec("android.webkit.WebView: void loadUrl(java.lang.String)", List.of(0))),
                List.of(new SanitizerSpec("android.webkit.URLUtil: boolean isHttpsUrl(java.lang.String)")),
                List.of("java.lang.String: java.lang.String concat(java.lang.String)"));
        RuleMatcher matcher = RuleMatcher.forRule(rule);

        assertThat(matcher.sourceFor("<android.content.Intent: java.lang.String getStringExtra(java.lang.String)>")).isPresent();
        assertThat(matcher.sinkFor("<android.webkit.WebView: void loadUrl(java.lang.String)>"))
                .get().extracting(SinkSpec::getTaintedArgs).isEqualTo(List.of(0));
        assertThat(matcher.sanitizerFor("<android.webkit.URLUtil: boolean isHttpsUrl(java.lang.String)>")).isPresent();
        assertThat(matcher.isPropagator("<java.lang.String: java.lang.String concat(java.lang.String)>")).isTrue();
        assertThat(matcher.sinkFor("<com.example.WebView: void loadUrl(java.lang.String)>")).isEmpty();
    }
}
