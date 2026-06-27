package com.oversecured.sast.reporter;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

class ReportCommandTest {

    private Path fixture(String name) throws Exception {
        return Paths.get(getClass().getResource("/fixtures/" + name).toURI());
    }

    @Test
    void run_writesHtmlAndSarifFiles(@TempDir Path tmp) throws Exception {
        Path html = tmp.resolve("report.html");
        Path sarif = tmp.resolve("report.sarif");

        int exit = new CommandLine(new ReportCommand()).execute(
                "--findings", fixture("findings-taint.json").toString(),
                fixture("findings-misconfig.json").toString(),
                "--out-html", html.toString(),
                "--out-sarif", sarif.toString());

        assertThat(exit).isEqualTo(0);
        assertThat(Files.exists(html)).isTrue();
        assertThat(Files.exists(sarif)).isTrue();
        assertThat(Files.readString(html)).contains("ANDROID_WEBVIEW_INTENT_LOADURL");
        assertThat(Files.readString(sarif)).contains("\"version\" : \"2.1.0\"");
    }

    @Test
    void run_emptyFindingsOption_writesValidEmptyReports(@TempDir Path tmp) throws Exception {
        Path html = tmp.resolve("out/report.html");
        Path sarif = tmp.resolve("out/report.sarif");

        int exit = new CommandLine(new ReportCommand()).execute(
                "--out-html", html.toString(),
                "--out-sarif", sarif.toString());

        assertThat(exit).isEqualTo(0);
        assertThat(Files.readString(html)).contains("No findings");
        assertThat(Files.readString(sarif)).contains("\"version\" : \"2.1.0\"");
    }
}
