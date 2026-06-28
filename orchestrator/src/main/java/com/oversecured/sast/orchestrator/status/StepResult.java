package com.oversecured.sast.orchestrator.status;

import com.oversecured.sast.common.Severity;
import java.util.List;
import java.util.Map;

public record StepResult(
        String nodeId,
        StepState state,
        String message,
        Map<String, Object> metrics,
        List<StepDiagnostic> diagnostics,
        List<ArtifactRef> artifacts,
        StepError error,
        List<String> findingsKeys,
        int findingCount,
        Map<Severity, Integer> severityCounts) {
    public StepResult {
        metrics = metrics == null ? Map.of() : Map.copyOf(metrics);
        diagnostics = diagnostics == null ? List.of() : List.copyOf(diagnostics);
        artifacts = artifacts == null ? List.of() : List.copyOf(artifacts);
        findingsKeys = findingsKeys == null ? List.of() : List.copyOf(findingsKeys);
        severityCounts = severityCounts == null ? Map.of() : Map.copyOf(severityCounts);
    }

    public static StepResult completed(
            String nodeId,
            String message,
            Map<String, Object> metrics,
            List<ArtifactRef> artifacts,
            List<String> findingsKeys,
            int findingCount,
            Map<Severity, Integer> severityCounts) {
        return completed(
                nodeId,
                message,
                metrics,
                List.of(),
                artifacts,
                findingsKeys,
                findingCount,
                severityCounts);
    }

    public static StepResult completed(
            String nodeId,
            String message,
            Map<String, Object> metrics,
            List<StepDiagnostic> diagnostics,
            List<ArtifactRef> artifacts,
            List<String> findingsKeys,
            int findingCount,
            Map<Severity, Integer> severityCounts) {
        return new StepResult(
                nodeId,
                StepState.COMPLETED,
                message,
                metrics,
                diagnostics,
                artifacts,
                null,
                findingsKeys,
                findingCount,
                severityCounts);
    }

    public static StepResult failed(String nodeId, String message, StepError error) {
        return failed(nodeId, message, error, List.of());
    }

    public static StepResult failed(
            String nodeId,
            String message,
            StepError error,
            List<StepDiagnostic> diagnostics) {
        return new StepResult(
                nodeId,
                StepState.FAILED,
                message,
                Map.of(),
                diagnostics,
                List.of(),
                error,
                List.of(),
                0,
                Map.of());
    }
}
