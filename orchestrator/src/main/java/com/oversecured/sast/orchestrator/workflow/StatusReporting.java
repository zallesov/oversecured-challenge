package com.oversecured.sast.orchestrator.workflow;

import com.oversecured.sast.orchestrator.status.StepResult;

import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Testable core: wraps an activity body with RUNNING/COMPLETED/FAILED status emissions.
 * The interceptor delegates here so that the logic can be unit-tested without Temporal mocks.
 */
public final class StatusReporting {

    private StatusReporting() {}

    @FunctionalInterface
    public interface ActivityBody {
        Object run() throws Exception;
    }

    /**
     * Runs {@code body}, emitting status events via {@code emitter} when {@code ctx} is present.
     *
     * @param ctx       callback context (may be null or absent — no emit in that case)
     * @param runId     run identifier for the event
     * @param nodeId    pipeline node identifier for the event
     * @param clock     supplies ISO-8601 timestamps
     * @param emitter   best-effort emitter (must not throw, but we guard it anyway)
     * @param extractor extracts a {@link StepResult} from the body's return value, or null if not applicable
     * @param body      the activity work to execute
     * @return the value returned by {@code body}
     * @throws Exception if {@code body} throws
     */
    public static Object runWithEmit(
            CallbackContext ctx,
            String runId,
            String nodeId,
            Supplier<String> clock,
            StatusEmitter emitter,
            Function<Object, StepResult> extractor,
            ActivityBody body) throws Exception {

        if (ctx == null || !ctx.isPresent()) {
            return body.run();
        }

        safeEmit(emitter, ctx, StatusEvent.running(runId, nodeId, clock.get()));

        try {
            Object out = body.run();
            // Try to emit a result event if the body produced a StepResult
            StepResult stepResult = null;
            try {
                stepResult = extractor.apply(out);
            } catch (Exception ignored) {
                // extractor failure: skip result emit
            }
            if (stepResult != null) {
                safeEmit(emitter, ctx, StatusEvent.fromResult(runId, nodeId, stepResult, clock.get()));
            }
            return out;
        } catch (Throwable t) {
            String msg = t.getMessage() == null ? t.getClass().getSimpleName() : t.getMessage();
            safeEmit(emitter, ctx, StatusEvent.failed(runId, nodeId, msg, clock.get()));
            if (t instanceof Error e) throw e;
            throw (Exception) t;
        }
    }

    private static void safeEmit(StatusEmitter emitter, CallbackContext ctx, StatusEvent event) {
        try {
            emitter.emit(ctx, event);
        } catch (Throwable ignored) {
            // emitter must never break activity execution
        }
    }
}
