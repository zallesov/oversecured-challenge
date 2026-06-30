package com.oversecured.sast.orchestrator.workflow;

/**
 * Best-effort status emission. Implementations MUST NOT throw.
 */
public interface StatusEmitter {
    /** Best-effort. MUST NOT throw. */
    void emit(CallbackContext ctx, StatusEvent event);
}
