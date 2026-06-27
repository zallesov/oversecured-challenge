package com.oversecured.sast.taint.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/** A YAML sanitizer signature. */
public final class SanitizerSpec {
    private final String signature;

    @JsonCreator
    public SanitizerSpec(@JsonProperty("signature") String signature) {
        this.signature = signature;
    }

    public String getSignature() {
        return signature;
    }
}
