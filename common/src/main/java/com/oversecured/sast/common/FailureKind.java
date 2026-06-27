package com.oversecured.sast.common;

/** Failure classification that drives CLI exit codes and Temporal retry policy. */
public enum FailureKind {
    /** Bad/corrupt input, invalid rule, unsupported artifact — retrying will not help. */
    PERMANENT,
    /** IO, resource exhaustion, transient environment fault — retrying may succeed. */
    TRANSIENT
}
