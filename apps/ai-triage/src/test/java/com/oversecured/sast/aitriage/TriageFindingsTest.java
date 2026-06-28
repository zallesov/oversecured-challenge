package com.oversecured.sast.aitriage;

import static org.assertj.core.api.Assertions.assertThat;

import com.oversecured.sast.common.Finding;
import com.oversecured.sast.common.FindingsDoc;
import com.oversecured.sast.common.Severity;
import java.util.List;
import org.junit.jupiter.api.Test;

class TriageFindingsTest {

    private TriageItem item(String rule, Verdict verdict, TriageSeverity sev) {
        return new TriageItem(new FindingRef(rule, "A.java", 47), verdict, sev, 0.9,
                "untrusted url reaches loadUrl", "use an allowlist", List.of("CWE-601", "M1"));
    }

    @Test
    void mapsActionableVerdictsToFindingsAndSkipsSafe() {
        TriageResult result = new TriageResult("m", "t", "summary", List.of(
                item("EXPLOIT_RULE", Verdict.EXPLOITABLE, TriageSeverity.CRITICAL),
                item("REVIEW_RULE", Verdict.NEEDS_REVIEW, TriageSeverity.MEDIUM),
                item("SAFE_RULE", Verdict.SAFE, TriageSeverity.INFO)));

        FindingsDoc doc = TriageFindings.toFindingsDoc(result);

        assertThat(doc.analyzer()).isEqualTo("ai-triage");
        assertThat(doc.findings()).hasSize(2); // safe is dropped

        Finding f = doc.findings().get(0);
        assertThat(f.ruleId()).isEqualTo("EXPLOIT_RULE");
        assertThat(f.severity()).isEqualTo(Severity.ERROR); // critical -> ERROR
        assertThat(f.message()).contains("exploitable").contains("untrusted url reaches loadUrl");
        assertThat(f.cwe()).isEqualTo("CWE-601");
        assertThat(f.owaspMobile()).isEqualTo("M1");
        assertThat(f.flow()).hasSize(1);
        assertThat(f.flow().get(0).file()).isEqualTo("A.java");
        assertThat(f.flow().get(0).line()).isEqualTo(47);
        assertThat(f.notes()).anyMatch(n -> n.contains("use an allowlist"));

        // needs-review (medium) -> WARNING
        assertThat(doc.findings().get(1).severity()).isEqualTo(Severity.WARNING);
    }

    @Test
    void toJsonEmbedsVerdictConfidenceAndFix() {
        TriageResult result = new TriageResult("m", "t", "summary", List.of(
                item("EXPLOIT_RULE", Verdict.EXPLOITABLE, TriageSeverity.CRITICAL)));

        String json = TriageFindings.toJson(result);

        assertThat(json).contains("\"verdict\" : \"exploitable\"");
        assertThat(json).contains("\"confidence\" : 0.9");
        assertThat(json).contains("\"fix\" : \"use an allowlist\"");
        assertThat(json).contains("\"analyzer\" : \"ai-triage\"");
    }

    @Test
    void emptyWhenAllSafeOrNoItems() {
        TriageResult result = new TriageResult("m", "t", "s",
                List.of(item("R", Verdict.SAFE, TriageSeverity.LOW)));
        assertThat(TriageFindings.toFindingsDoc(result).findings()).isEmpty();
    }
}
