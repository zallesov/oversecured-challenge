package com.oversecured.sast.orchestrator;

import com.oversecured.sast.common.Severity;
import com.oversecured.sast.orchestrator.status.ArtifactRef;
import com.oversecured.sast.orchestrator.status.StepError;
import com.oversecured.sast.orchestrator.status.StepResult;
import com.oversecured.sast.orchestrator.workflow.StatusEvent;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class StatusEventTest {

    private static final String RUN_ID = "run-123";
    private static final String NODE_ID = "taint";
    private static final String OCCURRED_AT = "2026-06-30T12:00:00Z";

    @Test
    void fromResultCompletedHasCorrectFields() {
        StepResult result = StepResult.completed(
                NODE_ID,
                "ok",
                Map.of("durationMs", 42),
                List.<ArtifactRef>of(),
                List.of("key1", "key2"),
                2,
                Map.of(Severity.ERROR, 1, Severity.WARNING, 1));

        StatusEvent event = StatusEvent.fromResult(RUN_ID, NODE_ID, result, OCCURRED_AT);

        assertThat(event.runId()).isEqualTo(RUN_ID);
        assertThat(event.nodeId()).isEqualTo(NODE_ID);
        assertThat(event.state()).isEqualTo("COMPLETED");
        assertThat(event.message()).isEqualTo("ok");
        assertThat(event.findingCount()).isEqualTo(2);
        assertThat(event.findingsKeys()).containsExactlyInAnyOrder("key1", "key2");
        assertThat(event.severityCounts()).containsEntry("ERROR", 1).containsEntry("WARNING", 1);
        assertThat(event.error()).isNull();
        assertThat(event.occurredAt()).isEqualTo(OCCURRED_AT);
    }

    @Test
    void fromResultFailedHasErrorPopulated() {
        StepResult result = StepResult.failed(NODE_ID, "something went wrong", new StepError("IO_ERROR", "disk full"));

        StatusEvent event = StatusEvent.fromResult(RUN_ID, NODE_ID, result, OCCURRED_AT);

        assertThat(event.state()).isEqualTo("FAILED");
        assertThat(event.error()).isNotNull();
        assertThat(event.error().kind()).isEqualTo("IO_ERROR");
        assertThat(event.error().message()).isEqualTo("disk full");
        assertThat(event.findingCount()).isEqualTo(0);
    }

    @Test
    void runningEventHasEmptyCollections() {
        StatusEvent event = StatusEvent.running(RUN_ID, NODE_ID, OCCURRED_AT);

        assertThat(event.state()).isEqualTo("RUNNING");
        assertThat(event.message()).isNull();
        assertThat(event.findingCount()).isEqualTo(0);
        assertThat(event.findingsKeys()).isEmpty();
        assertThat(event.metrics()).isEmpty();
        assertThat(event.severityCounts()).isEmpty();
        assertThat(event.error()).isNull();
    }

    @Test
    void failedFactoryCreatesFailedEvent() {
        StatusEvent event = StatusEvent.failed(RUN_ID, NODE_ID, "activity timed out", OCCURRED_AT);

        assertThat(event.state()).isEqualTo("FAILED");
        assertThat(event.message()).isEqualTo("activity timed out");
        assertThat(event.error()).isNotNull();
        assertThat(event.error().kind()).isEqualTo("UNKNOWN");
        assertThat(event.error().message()).isEqualTo("activity timed out");
    }
}
