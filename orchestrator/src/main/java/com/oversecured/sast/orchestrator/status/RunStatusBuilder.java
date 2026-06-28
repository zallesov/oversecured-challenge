package com.oversecured.sast.orchestrator.status;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;

public class RunStatusBuilder {
    private final String runId;
    private final Supplier<Instant> timeSource;
    private final Instant runStartedAt;
    private final Map<String, MutableNodeStatus> nodesById = new LinkedHashMap<>();
    private StepState runState = StepState.RUNNING;
    private String runMessage = "Scan is running.";
    private Instant runFinishedAt;

    public RunStatusBuilder(String runId, List<NodeDefinition> definitions, Supplier<Instant> timeSource) {
        this.runId = runId;
        this.timeSource = Objects.requireNonNull(timeSource, "timeSource");
        this.runStartedAt = this.timeSource.get();
        for (NodeDefinition definition : definitions) {
            nodesById.put(definition.id(), new MutableNodeStatus(definition, runStartedAt));
        }
    }

    public void markRunning(String nodeId, String message) {
        MutableNodeStatus node = node(nodeId);
        Instant now = timeSource.get();
        node.state = StepState.RUNNING;
        node.message = message;
        node.startedAt = now;
    }

    public void markCompleted(StepResult result) {
        MutableNodeStatus node = node(result.nodeId());
        Instant now = timeSource.get();
        if (node.startedAt == null) {
            node.startedAt = now;
        }
        node.state = StepState.COMPLETED;
        node.message = result.message();
        node.finishedAt = now;
        node.durationMs = Duration.between(node.startedAt, now).toMillis();
        node.metrics = result.metrics();
        node.diagnostics = result.diagnostics();
        node.artifacts = result.artifacts();
        node.error = result.error();
        node.findingsKeys = result.findingsKeys();
        node.findingCount = result.findingCount();
        node.severityCounts = result.severityCounts();

        if (allNodesCompleted()) {
            runState = StepState.COMPLETED;
            runMessage = "Scan completed.";
            runFinishedAt = now;
        }
    }

    /**
     * Record a step that reports its own terminal state (COMPLETED or FAILED) without treating a
     * FAILED node as a run failure. Used for optional, fail-soft steps: the node reflects what
     * happened, but the run still completes once every node is terminal.
     */
    public void markSettled(StepResult result) {
        MutableNodeStatus node = node(result.nodeId());
        Instant now = timeSource.get();
        if (node.startedAt == null) {
            node.startedAt = now;
        }
        node.state = result.state() == StepState.FAILED ? StepState.FAILED : StepState.COMPLETED;
        node.message = result.message();
        node.finishedAt = now;
        node.durationMs = Duration.between(node.startedAt, now).toMillis();
        node.metrics = result.metrics();
        node.diagnostics = result.diagnostics();
        node.artifacts = result.artifacts();
        node.error = result.error();
        node.findingsKeys = result.findingsKeys();
        node.findingCount = result.findingCount();
        node.severityCounts = result.severityCounts();

        if (allNodesTerminal()) {
            runState = StepState.COMPLETED;
            runMessage = anyNodeFailed() ? "Scan completed with warnings." : "Scan completed.";
            runFinishedAt = now;
        }
    }

    public void markFailed(StepResult result) {
        MutableNodeStatus node = node(result.nodeId());
        Instant now = timeSource.get();
        if (node.startedAt == null) {
            node.startedAt = now;
        }
        node.state = StepState.FAILED;
        node.message = result.message();
        node.finishedAt = now;
        node.durationMs = Duration.between(node.startedAt, now).toMillis();
        node.metrics = result.metrics();
        node.diagnostics = result.diagnostics();
        node.artifacts = result.artifacts();
        node.error = result.error();
        node.findingsKeys = result.findingsKeys();
        node.findingCount = result.findingCount();
        node.severityCounts = result.severityCounts();

        runState = StepState.FAILED;
        runMessage = result.message();
        runFinishedAt = now;
    }

    public RunStatus snapshot() {
        List<NodeStatus> nodes = new ArrayList<>();
        for (MutableNodeStatus node : nodesById.values()) {
            nodes.add(node.snapshot());
        }
        return new RunStatus(
                runId,
                runState,
                runMessage,
                runStartedAt.toString(),
                runFinishedAt == null ? null : runFinishedAt.toString(),
                runFinishedAt == null ? null : Duration.between(runStartedAt, runFinishedAt).toMillis(),
                nodes);
    }

    private boolean allNodesCompleted() {
        return nodesById.values().stream().allMatch(node -> node.state == StepState.COMPLETED);
    }

    private boolean allNodesTerminal() {
        return nodesById.values().stream()
                .allMatch(node -> node.state == StepState.COMPLETED || node.state == StepState.FAILED);
    }

    private boolean anyNodeFailed() {
        return nodesById.values().stream().anyMatch(node -> node.state == StepState.FAILED);
    }

    private MutableNodeStatus node(String nodeId) {
        MutableNodeStatus node = nodesById.get(nodeId);
        if (node == null) {
            throw new IllegalArgumentException("Unknown status node: " + nodeId);
        }
        return node;
    }

    public record NodeDefinition(String id, String label, String kind) {
    }

    private static final class MutableNodeStatus {
        private final NodeDefinition definition;
        private final Instant queuedAt;
        private StepState state = StepState.QUEUED;
        private String message = "Queued.";
        private Instant startedAt;
        private Instant finishedAt;
        private Long durationMs;
        private Map<String, Object> metrics = Map.of();
        private List<StepDiagnostic> diagnostics = List.of();
        private List<ArtifactRef> artifacts = List.of();
        private StepError error;
        private List<String> findingsKeys = List.of();
        private int findingCount;
        private Map<com.oversecured.sast.common.Severity, Integer> severityCounts = Map.of();

        private MutableNodeStatus(NodeDefinition definition, Instant queuedAt) {
            this.definition = definition;
            this.queuedAt = queuedAt;
        }

        private NodeStatus snapshot() {
            return new NodeStatus(
                    definition.id(),
                    definition.label(),
                    definition.kind(),
                    state,
                    message,
                    queuedAt.toString(),
                    startedAt == null ? null : startedAt.toString(),
                    finishedAt == null ? null : finishedAt.toString(),
                    durationMs,
                    metrics,
                    diagnostics,
                    artifacts,
                    error,
                    findingsKeys,
                    findingCount,
                    severityCounts);
        }
    }
}
