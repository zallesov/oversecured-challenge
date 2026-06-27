package com.oversecured.sast.taint.manifest;

import static org.assertj.core.api.Assertions.assertThat;

import com.oversecured.sast.common.ComponentFact;
import com.oversecured.sast.common.FlowStep;
import com.oversecured.sast.common.ManifestFacts;
import com.oversecured.sast.taint.flow.CandidateFinding;
import com.oversecured.sast.taint.model.ManifestConditions;
import java.util.List;
import org.junit.jupiter.api.Test;

class ReachabilityFilterTest {
    @Test
    void keepsExportedAndIccReachableFindingsAndSuppressesPrivateFindings() {
        ManifestFacts facts = new ManifestFacts("com.example", List.of(
                new ComponentFact("com.example.ExportedActivity", "activity", true, List.of(), false, null),
                new ComponentFact("com.example.PrivateActivity", "activity", false, List.of(), false, null),
                new ComponentFact("com.example.TargetActivity", "activity", false, List.of(), false, null)), List.of());
        ReachabilityFilter filter = new ReachabilityFilter(facts);
        ManifestConditions conditions = new ManifestConditions(true);

        CandidateFinding exported = CandidateFinding.testOnly("R", "com.example.ExportedActivity",
                List.of(new FlowStep("A.java", 1, "source")), List.of());
        CandidateFinding privateOnly = CandidateFinding.testOnly("R", "com.example.PrivateActivity",
                List.of(new FlowStep("B.java", 1, "source")), List.of());
        CandidateFinding iccReachable = CandidateFinding.testOnly("R", "com.example.TargetActivity",
                List.of(new FlowStep("A.java", 2, "putExtra(\"url\") + startActivity")), List.of());

        assertThat(filter.keep(exported, conditions)).isTrue();
        assertThat(filter.keep(privateOnly, conditions)).isFalse();
        assertThat(filter.keep(iccReachable, conditions)).isTrue();
    }
}
