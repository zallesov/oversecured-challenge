package com.oversecured.sast.orchestrator;

import java.util.ArrayList;
import java.util.List;

public record AnalysisPlan(
        String runId,
        ArtifactKeys keys,
        List<TaintAnalysis> taintAnalyses,
        ManifestMisconfigAnalysis manifestMisconfig,
        ReportConfig report) {

    public AnalysisPlan {
        taintAnalyses = List.copyOf(taintAnalyses);
    }

    public static AnalysisPlan defaultPlan(String runId) {
        ArtifactKeys keys = ArtifactKeys.forRun(runId);
        return new AnalysisPlan(
                runId,
                keys,
                List.of(
                        new TaintAnalysis(
                                "webview",
                                "rules/webview.yaml",
                                keys.rootKey() + "/findings-webview.json"),
                        new TaintAnalysis(
                                "pathtraversal",
                                "rules/pathtraversal.yaml",
                                keys.rootKey() + "/findings-pathtraversal.json")),
                new ManifestMisconfigAnalysis(
                        "manifest-misconfig",
                        "rules/misconfig.yaml",
                        keys.rootKey() + "/findings-misconfig.json"),
                new ReportConfig(
                        keys.rootKey() + "/report.html",
                        keys.rootKey() + "/report.sarif"));
    }

    public List<String> findingsKeysForReporter() {
        List<String> keys = new ArrayList<>();
        for (TaintAnalysis analysis : taintAnalyses) {
            keys.add(analysis.findingsKey());
        }
        keys.add(manifestMisconfig.findingsKey());
        return List.copyOf(keys);
    }

    public record TaintAnalysis(String name, String rulePath, String findingsKey) {
    }

    public record ManifestMisconfigAnalysis(String name, String rulePath, String findingsKey) {
    }

    public record ReportConfig(String htmlKey, String sarifKey) {
    }
}
