package com.oversecured.sast.aitriage;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum TriageSeverity {
    CRITICAL, HIGH, MEDIUM, LOW, INFO;

    @JsonValue
    public String json() {
        return name().toLowerCase();
    }

    @JsonCreator
    public static TriageSeverity fromJson(String value) {
        return valueOf(value.toUpperCase());
    }
}
