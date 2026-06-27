package com.oversecured.sast.common;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class JsonRoundTripTest {

    @Test
    void flowStepHoldsItsComponents() {
        FlowStep step = new FlowStep("DeeplinkActivity.java", 47, "source: getQueryParameter");
        assertThat(step.file()).isEqualTo("DeeplinkActivity.java");
        assertThat(step.line()).isEqualTo(47);
        assertThat(step.label()).isEqualTo("source: getQueryParameter");
    }

    @Test
    void severityHasThreeLevels() {
        assertThat(Severity.values())
                .containsExactly(Severity.ERROR, Severity.WARNING, Severity.NOTE);
    }

    @Test
    void findingsDocHoldsFindings() {
        Finding f = new Finding(
                "ANDROID_WEBVIEW_INTENT_LOADURL",
                "webview-open-redirect",
                Severity.ERROR,
                "Untrusted deeplink data flows into WebView.loadUrl",
                "CWE-601",
                "M1",
                List.of(new FlowStep("WebViewActivity.java", 20, "sink: loadUrl")),
                List.of("incomplete-sanitizer: host.endsWith bypassable"));
        FindingsDoc doc = new FindingsDoc("taint-engine", List.of(f));

        assertThat(doc.analyzer()).isEqualTo("taint-engine");
        assertThat(doc.findings()).hasSize(1);
        Finding only = doc.findings().get(0);
        assertThat(only.ruleId()).isEqualTo("ANDROID_WEBVIEW_INTENT_LOADURL");
        assertThat(only.vulnerabilityClass()).isEqualTo("webview-open-redirect");
        assertThat(only.severity()).isEqualTo(Severity.ERROR);
        assertThat(only.cwe()).isEqualTo("CWE-601");
        assertThat(only.owaspMobile()).isEqualTo("M1");
        assertThat(only.flow()).hasSize(1);
        assertThat(only.notes()).containsExactly("incomplete-sanitizer: host.endsWith bypassable");
    }

    @Test
    void findingsDocSurvivesJsonRoundTrip() {
        FindingsDoc original = new FindingsDoc(
                "taint-engine",
                List.of(new Finding(
                        "ANDROID_WEBVIEW_INTENT_LOADURL",
                        "webview-open-redirect",
                        Severity.ERROR,
                        "msg",
                        "CWE-601",
                        "M1",
                        List.of(
                                new FlowStep("DeeplinkActivity.java", 47, "source"),
                                new FlowStep("WebViewActivity.java", 20, "sink")),
                        List.of("incomplete-sanitizer"))));

        byte[] json = Json.writeBytes(original);
        FindingsDoc back = Json.read(json, FindingsDoc.class);

        assertThat(back).isEqualTo(original);
    }
}
