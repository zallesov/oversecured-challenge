package com.oversecured.sast.decompiler;

import com.oversecured.sast.common.FailureKind;
import com.oversecured.sast.common.PipelineException;

/** Thrown when decompilation cannot proceed; carries a {@link FailureKind} and a CLI-ready message. */
public class DecompilerException extends PipelineException {

    public DecompilerException(FailureKind kind, String message) {
        super(kind, message);
    }

    public DecompilerException(FailureKind kind, String message, Throwable cause) {
        super(kind, message, cause);
    }
}
