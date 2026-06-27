package com.oversecured.sast.reporter;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

class ReporterEndToEndTest {

    private Path fixture(String name) throws Exception {
        return Paths.get(getClass().getResource("/fixtures/" + name).toURI());
    }

    @Test
    void fullRun_twoFindingsDocs_producesValidHtmlAndSarif(@TempDir Path tmp) throws Exception {
        Path html = tmp.resolve("report.html");
        Path sarif = tmp.resolve("report.sarif");

        int exit = new CommandLine(new ReportCommand()).execute(
                "--findings", fixture("findings-taint.json").toString(),
                fixture("findings-misconfig.json").toString(),
                "--out-html", html.toString(),
                "--out-sarif", sarif.toString());
        assertThat(exit).isEqualTo(0);

        String htmlText = Files.readString(html);
        assertThat(htmlText).startsWith("<!DOCTYPE html>");
        assertThat(htmlText).contains("</html>");
        assertThat(htmlText).contains("ERROR").contains("WARNING");
        assertThat(htmlText).contains("source: Uri.getQueryParameter(&quot;url&quot;)");
        assertThat(htmlText).contains("DeeplinkActivity.java:47");
        assertThat(htmlText).contains("DeeplinkActivity.java:51");
        assertThat(htmlText).contains("WebViewActivity.java:20");
        assertThat(htmlText).contains("sink: WebView.loadUrl(url)");
        assertThat(htmlText).contains("WebViewActivity.java:22");
        assertThat(htmlText).contains("incomplete-sanitizer");
        assertThat(htmlText).contains("ANDROID_EXPORTED_NO_PERMISSION");
        assertThat(htmlText).contains("AndroidManifest.xml:12");

        JsonNode root = FindingsMerger.mapper().readTree(Files.readString(sarif));
        assertThat(root.get("version").asText()).isEqualTo("2.1.0");
        assertThat(root.get("runs")).hasSize(1);
        JsonNode results = root.get("runs").get(0).get("results");
        assertThat(results).hasSize(2);

        JsonNode taint = results.get(0);
        assertThat(taint.get("ruleId").asText()).isEqualTo("ANDROID_WEBVIEW_INTENT_LOADURL");
        JsonNode tfLocations =
                taint.get("codeFlows").get(0).get("threadFlows").get(0).get("locations");
        assertThat(tfLocations).hasSize(4);
        assertThat(tfLocations.get(0).get("location").get("physicalLocation")
                .get("region").get("startLine").asInt()).isEqualTo(47);
        assertThat(tfLocations.get(1).get("location").get("physicalLocation")
                .get("region").get("startLine").asInt()).isEqualTo(51);
        assertThat(tfLocations.get(2).get("location").get("physicalLocation")
                .get("region").get("startLine").asInt()).isEqualTo(20);
        assertThat(tfLocations.get(3).get("location").get("physicalLocation")
                .get("region").get("startLine").asInt()).isEqualTo(22);
    }

    @Test
    void fullRun_noFindings_producesValidEmptyReports(@TempDir Path tmp) throws Exception {
        Path html = tmp.resolve("report.html");
        Path sarif = tmp.resolve("report.sarif");

        int exit = new CommandLine(new ReportCommand()).execute(
                "--out-html", html.toString(),
                "--out-sarif", sarif.toString());
        assertThat(exit).isEqualTo(0);

        assertThat(Files.readString(html)).startsWith("<!DOCTYPE html>");
        assertThat(Files.readString(html)).contains("No findings");

        JsonNode root = FindingsMerger.mapper().readTree(Files.readString(sarif));
        assertThat(root.get("version").asText()).isEqualTo("2.1.0");
        assertThat(root.get("runs")).hasSize(1);
        assertThat(root.get("runs").get(0).get("results")).hasSize(0);
    }
}
