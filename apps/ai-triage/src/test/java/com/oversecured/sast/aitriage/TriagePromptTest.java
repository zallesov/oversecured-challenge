package com.oversecured.sast.aitriage;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class TriagePromptTest {

    @Test
    void systemPromptNamesVerdicts() {
        assertThat(TriagePrompt.SYSTEM)
                .contains("exploitable")
                .contains("needs-review")
                .contains("safe");
    }

    @Test
    void renderFindingsListsRefsAndFlow() {
        TriageFinding f = new TriageFinding(
                "RULE_X", "error", "msg", "CWE-601", "M1",
                List.of(new TriageFlowStep("A.java", 47, "source: x"),
                        new TriageFlowStep("B.java", 22, "sink: y")),
                new FindingRef("RULE_X", "A.java", 47));

        String text = TriagePrompt.renderFindings(List.of(f));

        assertThat(text).contains("Triage these 1 findings");
        assertThat(text).contains("[1] ruleId: RULE_X");
        assertThat(text).contains("A.java:47");
        assertThat(text).contains("B.java:22");
        assertThat(text).contains("ref: {ruleId: RULE_X, file: A.java, line: 47}");
    }
}
