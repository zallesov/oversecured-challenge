package com.oversecured.sast.common;

/** Base for all pipeline step failures; carries a {@link FailureKind} for the boundary to act on. */
public class PipelineException extends RuntimeException {

    private final FailureKind kind;

    public PipelineException(FailureKind kind, String message) {
        super(message);
        this.kind = kind;
    }

    public PipelineException(FailureKind kind, String message, Throwable cause) {
        super(message, cause);
        this.kind = kind;
    }

    public FailureKind kind() {
        return kind;
    }
}
