package com.oversecured.sast.reporter;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.oversecured.sast.common.Finding;
import com.oversecured.sast.common.FlowStep;
import com.oversecured.sast.common.Severity;
import java.util.List;
import org.junit.jupiter.api.Test;

class SarifReportWriterTest {

    private Finding taint() {
        return new Finding(
                "ANDROID_WEBVIEW_INTENT_LOADURL", "webview-open-redirect", Severity.ERROR,
                "Untrusted deeplink data flows into WebView.loadUrl", "CWE-601", "M1",
                List.of(
                        new FlowStep("DeeplinkActivity.java", 47, "source"),
                        new FlowStep("DeeplinkActivity.java", 51, "putExtra"),
                        new FlowStep("WebViewActivity.java", 20, "getStringExtra"),
                        new FlowStep("WebViewActivity.java", 22, "sink")),
                List.of("incomplete-sanitizer"));
    }

    private Finding misconfig() {
        return new Finding(
                "ANDROID_EXPORTED_NO_PERMISSION", "manifest-misconfig", Severity.WARNING,
                "Exported activity without permission", "CWE-926", "M1",
                List.of(), List.of());
    }

    @Test
    void toSarif_emitsValidV210WithRulesAndResults() {
        JsonNode root = new SarifReportWriter().toSarif(List.of(taint(), misconfig()));

        assertThat(root.get("version").asText()).isEqualTo("2.1.0");
        assertThat(root.get("runs")).hasSize(1);

        JsonNode run = root.get("runs").get(0);
        JsonNode rules = run.get("tool").get("driver").get("rules");
        assertThat(rules).hasSize(2);
        assertThat(rules.get(0).get("id").asText()).isEqualTo("ANDROID_WEBVIEW_INTENT_LOADURL");
        assertThat(rules.get(0).get("properties").get("cwe").asText()).isEqualTo("CWE-601");

        JsonNode results = run.get("results");
        assertThat(results).hasSize(2);

        JsonNode taintResult = results.get(0);
        assertThat(taintResult.get("ruleId").asText()).isEqualTo("ANDROID_WEBVIEW_INTENT_LOADURL");
        assertThat(taintResult.get("ruleIndex").asInt()).isEqualTo(0);
        assertThat(taintResult.get("level").asText()).isEqualTo("error");

        JsonNode tfLocations =
                taintResult.get("codeFlows").get(0).get("threadFlows").get(0).get("locations");
        assertThat(tfLocations).hasSize(4);
        assertThat(tfLocations.get(0).get("location").get("physicalLocation")
                .get("region").get("startLine").asInt()).isEqualTo(47);
        assertThat(tfLocations.get(3).get("location").get("physicalLocation")
                .get("region").get("startLine").asInt()).isEqualTo(22);

        JsonNode warnResult = results.get(1);
        assertThat(warnResult.get("level").asText()).isEqualTo("warning");
        assertThat(warnResult.has("codeFlows")).isFalse();
    }

    @Test
    void toSarif_emptyInput_oneRunZeroResults() {
        JsonNode root = new SarifReportWriter().toSarif(List.of());
        assertThat(root.get("version").asText()).isEqualTo("2.1.0");
        assertThat(root.get("runs")).hasSize(1);
        assertThat(root.get("runs").get(0).get("results")).hasSize(0);
        assertThat(root.get("runs").get(0).get("tool").get("driver").get("rules")).hasSize(0);
    }
}
