package com.oversecured.sast.orchestrator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class AnalysisPlanTest {

    @Test
    void defaultPlanDefinesAllRequiredBranchesAndOutputs() {
        AnalysisPlan plan = AnalysisPlan.defaultPlan("ovaa-001");

        assertThat(plan.runId()).isEqualTo("ovaa-001");
        assertThat(plan.keys().sourcesDirKey()).isEqualTo("runs/ovaa-001/sources");
        assertThat(plan.keys().manifestKey()).isEqualTo("runs/ovaa-001/sources/AndroidManifest.xml");
        assertThat(plan.keys().astIndexDirKey()).isEqualTo("runs/ovaa-001/ast-index");
        assertThat(plan.keys().factsKey()).isEqualTo("runs/ovaa-001/facts.json");

        assertThat(plan.taintAnalyses())
                .extracting(AnalysisPlan.TaintAnalysis::name)
                .containsExactly("webview", "pathtraversal");
        assertThat(plan.taintAnalyses())
                .extracting(AnalysisPlan.TaintAnalysis::rulePath)
                .containsExactly("rules/webview.yaml", "rules/pathtraversal.yaml");
        assertThat(plan.taintAnalyses())
                .extracting(AnalysisPlan.TaintAnalysis::findingsKey)
                .containsExactly(
                        "runs/ovaa-001/findings-webview.json",
                        "runs/ovaa-001/findings-pathtraversal.json");

        assertThat(plan.manifestMisconfig().rulePath()).isEqualTo("rules/misconfig.yaml");
        assertThat(plan.manifestMisconfig().findingsKey()).isEqualTo("runs/ovaa-001/findings-misconfig.json");
        assertThat(plan.report().htmlKey()).isEqualTo("runs/ovaa-001/report.html");
        assertThat(plan.report().sarifKey()).isEqualTo("runs/ovaa-001/report.sarif");
    }

    @Test
    void allFindingKeysReturnInReporterInputOrder() {
        AnalysisPlan plan = AnalysisPlan.defaultPlan("run-7");

        assertThat(plan.findingsKeysForReporter())
                .containsExactly(
                        "runs/run-7/findings-webview.json",
                        "runs/run-7/findings-pathtraversal.json",
                        "runs/run-7/findings-misconfig.json");
    }

    @Test
    void runIdMustBeAStablePathSegment() {
        assertThatThrownBy(() -> AnalysisPlan.defaultPlan("../escape"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("runId");

        assertThatThrownBy(() -> AnalysisPlan.defaultPlan("contains space"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("runId");
    }
}
