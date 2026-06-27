package com.oversecured.sast.manifestfacts;

import com.oversecured.sast.common.FailureKind;
import com.oversecured.sast.common.PipelineException;

/** Thrown when manifest-facts extraction cannot proceed; carries a {@link FailureKind} and a CLI-ready message. */
public class ManifestFactsException extends PipelineException {

    public ManifestFactsException(FailureKind kind, String message) {
        super(kind, message);
    }

    public ManifestFactsException(FailureKind kind, String message, Throwable cause) {
        super(kind, message, cause);
    }
}
