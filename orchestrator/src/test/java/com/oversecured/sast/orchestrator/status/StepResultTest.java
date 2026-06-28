package com.oversecured.sast.orchestrator.status;

import static org.assertj.core.api.Assertions.assertThat;

import com.oversecured.sast.common.Severity;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class StepResultTest {
    @Test
    void completedAnalyzerResultIncludesArtifactsAndFindingSummary() {
        String findingsKey = "runs/run-1/findings-webview.json";

        StepResult result = StepResult.completed(
                "taint",
                "Completed taint analysis for 2 rules with 3 findings.",
                Map.of("ruleCount", 2),
                List.of(new ArtifactRef("findings", findingsKey)),
                List.of(findingsKey),
                3,
                Map.of(Severity.ERROR, 1, Severity.WARNING, 2));

        assertThat(result.nodeId()).isEqualTo("taint");
        assertThat(result.state()).isEqualTo(StepState.COMPLETED);
        assertThat(result.message()).isEqualTo("Completed taint analysis for 2 rules with 3 findings.");
        assertThat(result.metrics()).containsEntry("ruleCount", 2);
        assertThat(result.artifacts()).containsExactly(new ArtifactRef("findings", findingsKey));
        assertThat(result.findingsKeys()).containsExactly(findingsKey);
        assertThat(result.findingCount()).isEqualTo(3);
        assertThat(result.severityCounts()).containsEntry(Severity.ERROR, 1);
        assertThat(result.severityCounts()).containsEntry(Severity.WARNING, 2);
        assertThat(result.error()).isNull();
    }

    @Test
    void failedAnalyzerResultIncludesPermanentErrorAndNoFindings() {
        StepResult result = StepResult.failed(
                "decompile",
                "Decompilation failed.",
                new StepError("PERMANENT", "apktool exited with code 1"));

        assertThat(result.nodeId()).isEqualTo("decompile");
        assertThat(result.state()).isEqualTo(StepState.FAILED);
        assertThat(result.message()).isEqualTo("Decompilation failed.");
        assertThat(result.error()).isEqualTo(new StepError("PERMANENT", "apktool exited with code 1"));
        assertThat(result.findingCount()).isZero();
        assertThat(result.findingsKeys()).isEmpty();
        assertThat(result.severityCounts()).isEmpty();
    }
}
