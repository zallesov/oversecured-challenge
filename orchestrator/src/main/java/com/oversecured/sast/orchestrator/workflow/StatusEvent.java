package com.oversecured.sast.orchestrator.workflow;

import com.oversecured.sast.orchestrator.status.StepResult;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Wire-contract event POSTed to the callback URL.
 * Field names must match the JSON contract exactly.
 */
public record StatusEvent(
        String runId,
        String nodeId,
        String state,
        String message,
        String occurredAt,
        Map<String, Object> metrics,
        List<String> findingsKeys,
        int findingCount,
        Map<String, Integer> severityCounts,
        ErrorInfo error) {

    public record ErrorInfo(String kind, String message) {}

    /** RUNNING event: empty collections, no message, no error. */
    public static StatusEvent running(String runId, String nodeId, String occurredAt) {
        return new StatusEvent(
                runId, nodeId, "RUNNING", null, occurredAt,
                Map.of(), List.of(), 0, Map.of(), null);
    }

    /** Build event from an activity's returned StepResult (COMPLETED or FAILED soft).
     *  The {@code nodeId} parameter overrides {@code result.nodeId()} so that the RUNNING
     *  and COMPLETED/FAILED events for one activity always carry the same node identifier.
     */
    public static StatusEvent fromResult(String runId, String nodeId, StepResult result, String occurredAt) {
        Map<String, Integer> severityCounts = result.severityCounts() == null
                ? Map.of()
                : result.severityCounts().entrySet().stream()
                        .collect(Collectors.toMap(
                                e -> e.getKey().name(),
                                Map.Entry::getValue));

        ErrorInfo errorInfo = result.error() == null
                ? null
                : new ErrorInfo(result.error().kind(), result.error().message());

        return new StatusEvent(
                runId,
                nodeId,
                result.state().name(),
                result.message(),
                occurredAt,
                result.metrics() != null ? result.metrics() : Map.of(),
                result.findingsKeys() != null ? result.findingsKeys() : List.of(),
                result.findingCount(),
                severityCounts,
                errorInfo);
    }

    /** FAILED event from an unexpected exception (activity threw). */
    public static StatusEvent failed(String runId, String nodeId, String message, String occurredAt) {
        return new StatusEvent(
                runId, nodeId, "FAILED", message, occurredAt,
                Map.of(), List.of(), 0, Map.of(),
                new ErrorInfo("UNKNOWN", message));
    }
}
