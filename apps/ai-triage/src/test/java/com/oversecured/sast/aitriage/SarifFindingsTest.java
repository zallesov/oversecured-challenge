package com.oversecured.sast.aitriage;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class SarifFindingsTest {

    private Path fixture() throws Exception {
        return Path.of(getClass().getResource("/fixtures/report.sarif").toURI());
    }

    @Test
    void parsesResultWithFlowRuleMetadataAndRef() throws Exception {
        List<TriageFinding> findings = new SarifFindings().parse(fixture());

        assertThat(findings).hasSize(1);
        TriageFinding f = findings.get(0);
        assertThat(f.ruleId()).isEqualTo("ANDROID_WEBVIEW_INTENT_LOADURL");
        assertThat(f.level()).isEqualTo("error");
        assertThat(f.message()).contains("WebView.loadUrl");
        assertThat(f.cwe()).isEqualTo("CWE-601");
        assertThat(f.owaspMobile()).isEqualTo("M1");
        assertThat(f.flow()).hasSize(2);
        assertThat(f.flow().get(0)).isEqualTo(
                new TriageFlowStep("DeeplinkActivity.java", 47, "source: Uri.getQueryParameter(\"url\")"));
        assertThat(f.ref()).isEqualTo(new FindingRef("ANDROID_WEBVIEW_INTENT_LOADURL", "DeeplinkActivity.java", 47));
    }
}
