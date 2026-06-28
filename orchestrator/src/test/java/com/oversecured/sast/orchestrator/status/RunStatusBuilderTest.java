package com.oversecured.sast.orchestrator.status;

import static org.assertj.core.api.Assertions.assertThat;

import com.oversecured.sast.common.Severity;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class RunStatusBuilderTest {
    @Test
    void markRunningThenCompletedSetsNodeTimestampsDurationAndMetrics() {
        AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-06-28T10:00:00Z"));
        RunStatusBuilder builder = new RunStatusBuilder(
                "run-1",
                List.of(new RunStatusBuilder.NodeDefinition("taint", "Taint Analysis", "analyzer")),
                now::get);

        now.set(Instant.parse("2026-06-28T10:00:01Z"));
        builder.markRunning("taint", "Running taint analysis.");

        now.set(Instant.parse("2026-06-28T10:00:04Z"));
        builder.markCompleted(StepResult.completed(
                "taint",
                "Completed taint analysis.",
                Map.of("ruleCount", 2),
                List.of(),
                List.of(),
                0,
                Map.of(Severity.WARNING, 1)));

        RunStatus snapshot = builder.snapshot();
        NodeStatus node = snapshot.nodes().get(0);

        assertThat(node.state()).isEqualTo(StepState.COMPLETED);
        assertThat(node.startedAt()).isEqualTo("2026-06-28T10:00:01Z");
        assertThat(node.finishedAt()).isEqualTo("2026-06-28T10:00:04Z");
        assertThat(node.durationMs()).isEqualTo(3000);
        assertThat(node.metrics()).containsEntry("ruleCount", 2);
        assertThat(node.severityCounts()).containsEntry(Severity.WARNING, 1);
    }

    @Test
    void markFailedSetsRunAndNodeFailureTimestampsDurationAndErrorKind() {
        AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-06-28T10:00:00Z"));
        RunStatusBuilder builder = new RunStatusBuilder(
                "run-1",
                List.of(new RunStatusBuilder.NodeDefinition("decompile", "Decompile", "preparation")),
                now::get);

        now.set(Instant.parse("2026-06-28T10:00:02Z"));
        builder.markRunning("decompile", "Running decompile.");

        now.set(Instant.parse("2026-06-28T10:00:07Z"));
        builder.markFailed(StepResult.failed(
                "decompile",
                "Decompilation failed.",
                new StepError("PERMANENT", "apktool exited with code 1")));

        RunStatus snapshot = builder.snapshot();
        NodeStatus node = snapshot.nodes().get(0);

        assertThat(snapshot.state()).isEqualTo(StepState.FAILED);
        assertThat(snapshot.finishedAt()).isEqualTo("2026-06-28T10:00:07Z");
        assertThat(node.state()).isEqualTo(StepState.FAILED);
        assertThat(node.durationMs()).isEqualTo(5000);
        assertThat(node.error().kind()).isEqualTo("PERMANENT");
    }
}
