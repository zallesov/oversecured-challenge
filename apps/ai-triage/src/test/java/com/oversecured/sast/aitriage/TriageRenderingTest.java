package com.oversecured.sast.aitriage;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class TriageRenderingTest {

    private TriageResult sample() {
        return new TriageResult("openrouter/x", "2026-06-28T00:00:00Z", "1 exploitable.",
                List.of(new TriageItem(
                        new FindingRef("RULE_X", "A.java", 47),
                        Verdict.EXPLOITABLE, TriageSeverity.HIGH, 0.85,
                        "untrusted url reaches loadUrl", "use allowlist", List.of("CWE-601"))));
    }

    @Test
    void jsonRoundTripsAndLowercasesEnums() {
        String json = TriageJson.write(sample());

        assertThat(json).contains("\"verdict\" : \"exploitable\"");
        assertThat(json).contains("\"severity\" : \"high\"");
        TriageResult back = TriageJson.read(json);
        assertThat(back.items().get(0).verdict()).isEqualTo(Verdict.EXPLOITABLE);
        assertThat(back.items().get(0).ref().line()).isEqualTo(47);
    }

    @Test
    void markdownHasSummaryAndPerFindingSection() {
        String md = MarkdownRenderer.render(sample());

        assertThat(md).contains("# AI Triage");
        assertThat(md).contains("1 exploitable.");
        assertThat(md).contains("RULE_X");
        assertThat(md).contains("A.java:47");
        assertThat(md).contains("exploitable");
        assertThat(md).contains("use allowlist");
    }
}
