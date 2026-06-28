package com.oversecured.sast.orchestrator.status;

import com.oversecured.sast.common.Severity;
import java.util.List;
import java.util.Map;

public record NodeStatus(
        String id,
        String label,
        String kind,
        StepState state,
        String message,
        String queuedAt,
        String startedAt,
        String finishedAt,
        Long durationMs,
        Map<String, Object> metrics,
        List<StepDiagnostic> diagnostics,
        List<ArtifactRef> artifacts,
        StepError error,
        List<String> findingsKeys,
        int findingCount,
        Map<Severity, Integer> severityCounts) {
    public NodeStatus {
        metrics = metrics == null ? Map.of() : Map.copyOf(metrics);
        diagnostics = diagnostics == null ? List.of() : List.copyOf(diagnostics);
        artifacts = artifacts == null ? List.of() : List.copyOf(artifacts);
        findingsKeys = findingsKeys == null ? List.of() : List.copyOf(findingsKeys);
        severityCounts = severityCounts == null ? Map.of() : Map.copyOf(severityCounts);
    }
}
