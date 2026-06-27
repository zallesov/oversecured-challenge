package com.oversecured.sast.taint.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/** Rule manifest conditions; currently just reachable-from-exported. */
public final class ManifestConditions {
    private final boolean reachableFromExported;

    @JsonCreator
    public ManifestConditions(
            @JsonProperty("reachableFromExported") boolean reachableFromExported) {
        this.reachableFromExported = reachableFromExported;
    }

    public boolean isReachableFromExported() {
        return reachableFromExported;
    }
}
