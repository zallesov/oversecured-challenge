package com.oversecured.sast.orchestrator.workflow;

/** Per-job status callback target, propagated via Temporal header workflow→activity. */
public record CallbackContext(String url, String secret, String runId) {
    public boolean isPresent() {
        return url != null && !url.isBlank();
    }
}
