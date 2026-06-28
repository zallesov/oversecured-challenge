package com.oversecured.sast.orchestrator;

public record AnalysisResult(
        String htmlReportKey,
        String sarifReportKey,
        String aiTriageJsonKey,
        String aiTriageMdKey) {
}
