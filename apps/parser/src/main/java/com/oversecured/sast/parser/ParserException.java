package com.oversecured.sast.parser;

import com.oversecured.sast.common.FailureKind;
import com.oversecured.sast.common.PipelineException;

/** Thrown when the parser step cannot proceed; carries a {@link FailureKind} and a CLI-ready message. */
public class ParserException extends PipelineException {

    public ParserException(FailureKind kind, String message) {
        super(kind, message);
    }

    public ParserException(FailureKind kind, String message, Throwable cause) {
        super(kind, message, cause);
    }
}
