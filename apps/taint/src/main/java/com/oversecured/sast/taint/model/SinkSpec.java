package com.oversecured.sast.taint.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/** A YAML sink signature plus the tainted argument positions. */
public final class SinkSpec {
    private final String signature;
    private final List<Integer> taintedArgs;

    @JsonCreator
    public SinkSpec(
            @JsonProperty("signature") String signature,
            @JsonProperty("tainted_args") List<Integer> taintedArgs) {
        this.signature = signature;
        this.taintedArgs = taintedArgs == null ? List.of() : List.copyOf(taintedArgs);
    }

    public String getSignature() {
        return signature;
    }

    public List<Integer> getTaintedArgs() {
        return taintedArgs;
    }
}
