package com.oversecured.sast.aitriage;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AiTriageAnalyzerTest {

    private Path sarifFixture(Path dir) throws Exception {
        Path src = Path.of(getClass().getResource("/fixtures/report.sarif").toURI());
        Path dest = dir.resolve("report.sarif");
        Files.copy(src, dest);
        return dest;
    }

    @Test
    void writesSidecarFromEngineResult(@TempDir Path dir) throws Exception {
        Path sarif = sarifFixture(dir);
        TriageResult canned = new TriageResult("fake-model", "2026-06-28T00:00:00Z", "done",
                List.of(new TriageItem(new FindingRef("ANDROID_WEBVIEW_INTENT_LOADURL", "DeeplinkActivity.java", 47),
                        Verdict.EXPLOITABLE, TriageSeverity.HIGH, 0.9, "r", "f", List.of("CWE-601"))));
        AiTriageAnalyzer analyzer = new AiTriageAnalyzer(sources -> new TriageEngine() {
            public TriageResult triage(List<TriageFinding> f) {
                return canned;
            }

            public String modelName() {
                return "fake-model";
            }
        });

        Path outJson = dir.resolve("ai-triage.json");
        Path outMd = dir.resolve("ai-triage.md");
        analyzer.run(sarif, dir, outJson, outMd);

        TriageResult written = TriageJson.read(Files.readString(outJson));
        assertThat(written.items()).hasSize(1);
        assertThat(written.items().get(0).verdict()).isEqualTo(Verdict.EXPLOITABLE);
        assertThat(Files.readString(outMd)).contains("ANDROID_WEBVIEW_INTENT_LOADURL");
    }

    @Test
    void writesEmptySidecarWhenNoEngine(@TempDir Path dir) throws Exception {
        Path sarif = sarifFixture(dir);
        AiTriageAnalyzer analyzer = new AiTriageAnalyzer(sources -> null);

        Path outJson = dir.resolve("ai-triage.json");
        Path outMd = dir.resolve("ai-triage.md");
        analyzer.run(sarif, dir, outJson, outMd);

        TriageResult written = TriageJson.read(Files.readString(outJson));
        assertThat(written.items()).isEmpty();
        assertThat(written.summary()).contains("skipped");
        assertThat(Files.exists(outMd)).isTrue();
    }

    @Test
    void writesEmptySidecarWhenEngineThrows(@TempDir Path dir) throws Exception {
        Path sarif = sarifFixture(dir);
        AiTriageAnalyzer analyzer = new AiTriageAnalyzer(sources -> new TriageEngine() {
            public TriageResult triage(List<TriageFinding> f) {
                throw new RuntimeException("API down");
            }

            public String modelName() {
                return "boom";
            }
        });

        Path outJson = dir.resolve("ai-triage.json");
        Path outMd = dir.resolve("ai-triage.md");
        analyzer.run(sarif, dir, outJson, outMd); // must not throw

        assertThat(TriageJson.read(Files.readString(outJson)).items()).isEmpty();
    }
}
