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
                .containsExactly("webview", "pathtraversal", "intent-redirect", "file-theft",
                        "login-url-injection", "credential-log-leak");
        assertThat(plan.taintAnalyses())
                .extracting(AnalysisPlan.TaintAnalysis::rulePath)
                .containsExactly("rules/webview.yaml", "rules/pathtraversal.yaml",
                        "rules/intent-redirect.yaml", "rules/file-theft.yaml",
                        "rules/login-url-injection.yaml", "rules/credential-log-leak.yaml");
        assertThat(plan.taintAnalyses())
                .extracting(AnalysisPlan.TaintAnalysis::findingsKey)
                .containsExactly(
                        "runs/ovaa-001/findings-webview.json",
                        "runs/ovaa-001/findings-pathtraversal.json",
                        "runs/ovaa-001/findings-intent-redirect.json",
                        "runs/ovaa-001/findings-file-theft.json",
                        "runs/ovaa-001/findings-login-url-injection.json",
                        "runs/ovaa-001/findings-credential-log-leak.json");

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
                        "runs/run-7/findings-intent-redirect.json",
                        "runs/run-7/findings-file-theft.json",
                        "runs/run-7/findings-login-url-injection.json",
                        "runs/run-7/findings-credential-log-leak.json",
                        "runs/run-7/findings-misconfig.json");
    }

    @Test
    void forRulesMapsRuleNameToFileAndFindingsKey() {
        AnalysisPlan plan = AnalysisPlan.forRules("run-9", java.util.List.of("file-theft", "webview"));

        assertThat(plan.taintAnalyses())
                .extracting(AnalysisPlan.TaintAnalysis::name)
                .containsExactly("file-theft", "webview");
        assertThat(plan.taintAnalyses())
                .extracting(AnalysisPlan.TaintAnalysis::rulePath)
                .containsExactly("rules/file-theft.yaml", "rules/webview.yaml");
        assertThat(plan.taintAnalyses())
                .extracting(AnalysisPlan.TaintAnalysis::findingsKey)
                .containsExactly(
                        "runs/run-9/findings-file-theft.json",
                        "runs/run-9/findings-webview.json");
        // misconfig branch always present, independent of the taint selection
        assertThat(plan.manifestMisconfig().rulePath()).isEqualTo("rules/misconfig.yaml");
    }

    @Test
    void forRulesDeduplicatesPreservingFirstOrder() {
        AnalysisPlan plan = AnalysisPlan.forRules("r", java.util.List.of("webview", "file-theft", "webview"));

        assertThat(plan.taintAnalyses())
                .extracting(AnalysisPlan.TaintAnalysis::name)
                .containsExactly("webview", "file-theft");
    }

    @Test
    void forRulesRejectsEmptyMisconfigAndTraversal() {
        assertThatThrownBy(() -> AnalysisPlan.forRules("r", java.util.List.of()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("at least one");

        assertThatThrownBy(() -> AnalysisPlan.forRules("r", java.util.List.of("misconfig")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("misconfig");

        assertThatThrownBy(() -> AnalysisPlan.forRules("r", java.util.List.of("../secret")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("invalid rule name");
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
