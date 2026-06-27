package com.oversecured.sast.taint.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/** A YAML source signature. */
public final class SourceSpec {
    private final String signature;

    @JsonCreator
    public SourceSpec(@JsonProperty("signature") String signature) {
        this.signature = signature;
    }

    public String getSignature() {
        return signature;
    }
}
