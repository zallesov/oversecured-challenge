package com.oversecured.sast.aitriage;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class TriageResultTest {

    @Test
    void holdsItemsAndEnumsExposeJsonValues() {
        TriageItem item = new TriageItem(
                new FindingRef("RULE", "A.java", 47),
                Verdict.NEEDS_REVIEW,
                TriageSeverity.HIGH,
                0.8,
                "why",
                "fix",
                List.of("CWE-601"));
        TriageResult result = new TriageResult("m", "2026-06-28T00:00:00Z", "summary", List.of(item));

        assertThat(result.items()).hasSize(1);
        assertThat(result.items().get(0).ref().line()).isEqualTo(47);
        assertThat(Verdict.NEEDS_REVIEW.json()).isEqualTo("needs-review");
        assertThat(TriageSeverity.HIGH.json()).isEqualTo("high");
    }
}
