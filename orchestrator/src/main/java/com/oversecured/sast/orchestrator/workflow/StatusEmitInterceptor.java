package com.oversecured.sast.orchestrator.workflow;

import com.oversecured.sast.orchestrator.status.StepResult;
import io.temporal.common.interceptors.ActivityInboundCallsInterceptor;
import io.temporal.common.interceptors.ActivityInboundCallsInterceptorBase;
import io.temporal.common.interceptors.WorkerInterceptorBase;

import java.util.function.Function;

/**
 * Worker interceptor that wraps each activity execution with RUNNING/COMPLETED/FAILED
 * status emission via {@link StatusReporting}. Thin by design — logic lives in
 * {@link StatusReporting} for testability.
 */
public final class StatusEmitInterceptor extends WorkerInterceptorBase {

    /** Unwraps ActivityOutput → StepResult; returns null if the result is not a StepResult. */
    private static final Function<Object, StepResult> STEP_RESULT_EXTRACTOR = o -> {
        if (o instanceof ActivityInboundCallsInterceptor.ActivityOutput ao) {
            Object result = ao.getResult();
            return result instanceof StepResult s ? s : null;
        }
        return null;
    };

    private final StatusEmitter emitter;

    public StatusEmitInterceptor() {
        this(new HttpStatusEmitter());
    }

    public StatusEmitInterceptor(StatusEmitter emitter) {
        this.emitter = emitter;
    }

    @Override
    public ActivityInboundCallsInterceptor interceptActivity(ActivityInboundCallsInterceptor next) {
        return new ActivityInboundCallsInterceptorBase(next) {
            private String activityType;

            @Override
            public void init(io.temporal.activity.ActivityExecutionContext context) {
                this.activityType = context.getInfo().getActivityType();
                super.init(context);
            }

            @Override
            public ActivityOutput execute(ActivityInput input) {
                CallbackContext ctx = CallbackContextPropagator.current();
                String nodeId = ActivityNodeIds.nodeIdForActivityType(activityType);
                String runId = ctx == null ? null : ctx.runId();

                try {
                    return (ActivityOutput) StatusReporting.runWithEmit(
                            ctx, runId, nodeId,
                            () -> java.time.Instant.now().toString(),
                            emitter,
                            STEP_RESULT_EXTRACTOR,
                            () -> super.execute(input));
                } catch (RuntimeException e) {
                    throw e;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        };
    }
}
