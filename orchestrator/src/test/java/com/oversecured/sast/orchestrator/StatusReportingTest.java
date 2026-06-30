package com.oversecured.sast.orchestrator;

import com.oversecured.sast.common.Severity;
import com.oversecured.sast.orchestrator.status.ArtifactRef;
import com.oversecured.sast.orchestrator.status.StepError;
import com.oversecured.sast.orchestrator.status.StepResult;
import com.oversecured.sast.orchestrator.workflow.CallbackContext;
import com.oversecured.sast.orchestrator.workflow.StatusEmitter;
import com.oversecured.sast.orchestrator.workflow.StatusEvent;
import com.oversecured.sast.orchestrator.workflow.StatusReporting;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class StatusReportingTest {

    private static final String RUN_ID = "run-456";
    private static final String NODE_ID = "taint";
    private static final String OCCURRED_AT = "2026-06-30T12:00:00Z";
    private static final CallbackContext PRESENT_CTX = new CallbackContext("http://localhost:9000/cb", "secret", RUN_ID);
    private static final CallbackContext ABSENT_CTX_NULL_URL = new CallbackContext(null, null, null);
    private static final CallbackContext ABSENT_CTX_BLANK_URL = new CallbackContext("  ", null, null);

    // Extractor: passthrough for StepResult (no Temporal types needed)
    private static final Function<Object, StepResult> EXTRACTOR = o -> (StepResult) o;

    private static final StepResult COMPLETED_RESULT = StepResult.completed(
            NODE_ID, "done", Map.of(), List.<ArtifactRef>of(), List.of(), 0, Map.of());

    private static List<StatusEvent> capturingEmitter(List<StatusEvent> captured) {
        return captured; // returned for fluency; capture happens via reference
    }

    private static StatusEmitter newCapturing(List<StatusEvent> captured) {
        return (ctx, event) -> captured.add(event);
    }

    @Test
    void presentCtxCompletedStepResult_emitsRunningThenCompleted() throws Exception {
        List<StatusEvent> captured = new ArrayList<>();
        StatusEmitter emitter = newCapturing(captured);

        Object result = StatusReporting.runWithEmit(
                PRESENT_CTX, RUN_ID, NODE_ID,
                () -> OCCURRED_AT,
                emitter,
                EXTRACTOR,
                () -> COMPLETED_RESULT);

        assertThat(result).isSameAs(COMPLETED_RESULT);
        assertThat(captured).hasSize(2);
        assertThat(captured.get(0).state()).isEqualTo("RUNNING");
        assertThat(captured.get(1).state()).isEqualTo("COMPLETED");
    }

    @Test
    void presentCtxBodyThrows_emitsRunningThenFailed_rethrows() {
        List<StatusEvent> captured = new ArrayList<>();
        StatusEmitter emitter = newCapturing(captured);
        RuntimeException boom = new RuntimeException("boom");

        assertThatThrownBy(() -> StatusReporting.runWithEmit(
                PRESENT_CTX, RUN_ID, NODE_ID,
                () -> OCCURRED_AT,
                emitter,
                EXTRACTOR,
                () -> { throw boom; }))
                .isSameAs(boom);

        assertThat(captured).hasSize(2);
        assertThat(captured.get(0).state()).isEqualTo("RUNNING");
        assertThat(captured.get(1).state()).isEqualTo("FAILED");
    }

    @Test
    void absentCtxNullUrl_noEmits_bodyResultReturned() throws Exception {
        List<StatusEvent> captured = new ArrayList<>();
        StatusEmitter emitter = newCapturing(captured);

        Object result = StatusReporting.runWithEmit(
                ABSENT_CTX_NULL_URL, RUN_ID, NODE_ID,
                () -> OCCURRED_AT,
                emitter,
                EXTRACTOR,
                () -> COMPLETED_RESULT);

        assertThat(result).isSameAs(COMPLETED_RESULT);
        assertThat(captured).isEmpty();
    }

    @Test
    void nullCtx_noEmits_bodyResultReturned() throws Exception {
        List<StatusEvent> captured = new ArrayList<>();
        StatusEmitter emitter = newCapturing(captured);

        Object result = StatusReporting.runWithEmit(
                null, RUN_ID, NODE_ID,
                () -> OCCURRED_AT,
                emitter,
                EXTRACTOR,
                () -> COMPLETED_RESULT);

        assertThat(result).isSameAs(COMPLETED_RESULT);
        assertThat(captured).isEmpty();
    }

    @Test
    void absentCtxBlankUrl_noEmits_bodyResultReturned() throws Exception {
        List<StatusEvent> captured = new ArrayList<>();
        StatusEmitter emitter = newCapturing(captured);

        Object result = StatusReporting.runWithEmit(
                ABSENT_CTX_BLANK_URL, RUN_ID, NODE_ID,
                () -> OCCURRED_AT,
                emitter,
                EXTRACTOR,
                () -> COMPLETED_RESULT);

        assertThat(result).isSameAs(COMPLETED_RESULT);
        assertThat(captured).isEmpty();
    }

    @Test
    void emitterThrows_runWithEmit_stillReturnsBodyResult() throws Exception {
        StatusEmitter throwingEmitter = (ctx, event) -> { throw new RuntimeException("emitter broke"); };

        Object result = StatusReporting.runWithEmit(
                PRESENT_CTX, RUN_ID, NODE_ID,
                () -> OCCURRED_AT,
                throwingEmitter,
                EXTRACTOR,
                () -> COMPLETED_RESULT);

        assertThat(result).isSameAs(COMPLETED_RESULT);
    }

    @Test
    void httpStatusEmitter_unreachableUrl_doesNotThrow() {
        var emitter = new com.oversecured.sast.orchestrator.workflow.HttpStatusEmitter();
        CallbackContext ctx = new CallbackContext("http://127.0.0.1:1/x", "secret", "run-1");
        StatusEvent event = StatusEvent.running("run-1", "taint", OCCURRED_AT);
        // Must not throw
        emitter.emit(ctx, event);
    }
}
