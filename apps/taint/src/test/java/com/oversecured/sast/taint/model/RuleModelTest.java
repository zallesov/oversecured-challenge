package com.oversecured.sast.taint.model;

import static org.assertj.core.api.Assertions.assertThat;

import com.oversecured.sast.common.Severity;
import java.util.List;
import org.junit.jupiter.api.Test;

class RuleModelTest {
    @Test
    void gettersExposeRulesPlanContract() {
        Rule rule = new Rule(
                "ANDROID_WEBVIEW_INTENT_LOADURL",
                "webview-open-redirect",
                Severity.ERROR,
                "CWE-601",
                "M1",
                "Untrusted Intent data flows into WebView.loadUrl",
                new ManifestConditions(true),
                List.of(new SourceSpec("android.content.Intent: java.lang.String getStringExtra(java.lang.String)")),
                List.of(new SinkSpec("android.webkit.WebView: void loadUrl(java.lang.String)", List.of(0))),
                List.of(new SanitizerSpec("android.webkit.URLUtil: boolean isHttpsUrl(java.lang.String)")),
                List.of("java.lang.String: java.lang.String concat(java.lang.String)"));
        RuleFile file = new RuleFile(1, List.of(rule));

        assertThat(file.getVersion()).isEqualTo(1);
        assertThat(file.getRules()).containsExactly(rule);
        assertThat(rule.getId()).isEqualTo("ANDROID_WEBVIEW_INTENT_LOADURL");
        assertThat(rule.getVulnerabilityClass()).isEqualTo("webview-open-redirect");
        assertThat(rule.getSeverity()).isEqualTo(Severity.ERROR);
        assertThat(rule.getCwe()).isEqualTo("CWE-601");
        assertThat(rule.getOwaspMobile()).isEqualTo("M1");
        assertThat(rule.getMessage()).contains("WebView");
        assertThat(rule.getManifestConditions().isReachableFromExported()).isTrue();
        assertThat(rule.getSources().get(0).getSignature()).startsWith("android.content.Intent:");
        assertThat(rule.getSinks().get(0).getTaintedArgs()).containsExactly(0);
        assertThat(rule.getSanitizers().get(0).getSignature()).contains("isHttpsUrl");
        assertThat(rule.getPropagators()).hasSize(1);
    }
}
