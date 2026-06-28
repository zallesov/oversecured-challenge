package com.oversecured.sast.aitriage;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum Verdict {
    EXPLOITABLE("exploitable"),
    NEEDS_REVIEW("needs-review"),
    SAFE("safe");

    private final String json;

    Verdict(String json) {
        this.json = json;
    }

    @JsonValue
    public String json() {
        return json;
    }

    @JsonCreator
    public static Verdict fromJson(String value) {
        for (Verdict v : values()) {
            if (v.json.equals(value)) {
                return v;
            }
        }
        throw new IllegalArgumentException("unknown verdict: " + value);
    }
}
