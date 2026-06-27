package com.oversecured.sast.reporter;

import static org.assertj.core.api.Assertions.assertThat;

import com.oversecured.sast.common.Finding;
import com.oversecured.sast.common.FlowStep;
import com.oversecured.sast.common.Severity;
import java.util.List;
import org.junit.jupiter.api.Test;

class HtmlReportRendererTest {

    private Finding taint() {
        return new Finding(
                "ANDROID_WEBVIEW_INTENT_LOADURL", "webview-open-redirect", Severity.ERROR,
                "Untrusted deeplink data flows into WebView.loadUrl", "CWE-601", "M1",
                List.of(
                        new FlowStep("DeeplinkActivity.java", 47, "source: getQueryParameter"),
                        new FlowStep("WebViewActivity.java", 22, "sink: WebView.loadUrl")),
                List.of("incomplete-sanitizer: host.endsWith bypassable"));
    }

    @Test
    void render_containsStructureFlowStepsAndNotes() {
        String html = new HtmlReportRenderer().render(List.of(taint()));

        assertThat(html).startsWith("<!DOCTYPE html>");
        assertThat(html).contains("<html").contains("</html>");
        assertThat(html).contains("ANDROID_WEBVIEW_INTENT_LOADURL");
        assertThat(html).contains("CWE-601");
        assertThat(html).contains("source: getQueryParameter");
        assertThat(html).contains("DeeplinkActivity.java:47");
        assertThat(html).contains("sink: WebView.loadUrl");
        assertThat(html).contains("WebViewActivity.java:22");
        assertThat(html).contains("incomplete-sanitizer: host.endsWith bypassable");
        assertThat(html).contains("ERROR");
    }

    @Test
    void render_escapesUntrustedText() {
        Finding xss = new Finding(
                "R", "c", Severity.NOTE, "<script>alert(1)</script>", "CWE-79", "M7",
                List.of(new FlowStep("A.java", 1, "<img src=x>")), List.of());
        String html = new HtmlReportRenderer().render(List.of(xss));

        assertThat(html).doesNotContain("<script>alert(1)</script>");
        assertThat(html).contains("&lt;script&gt;alert(1)&lt;/script&gt;");
        assertThat(html).contains("&lt;img src=x&gt;");
    }

    @Test
    void render_emptyInput_returnsValidEmptyDocument() {
        String html = new HtmlReportRenderer().render(List.of());

        assertThat(html).startsWith("<!DOCTYPE html>");
        assertThat(html).contains("</html>");
        assertThat(html).contains("No findings");
    }
}
