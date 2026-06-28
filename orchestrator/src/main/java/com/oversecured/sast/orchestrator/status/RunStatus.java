package com.oversecured.sast.orchestrator.status;

import java.util.List;

public record RunStatus(
        String runId,
        StepState state,
        String message,
        String startedAt,
        String finishedAt,
        Long durationMs,
        List<NodeStatus> nodes) {
    public RunStatus {
        nodes = nodes == null ? List.of() : List.copyOf(nodes);
    }
}
