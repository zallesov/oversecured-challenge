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
        if (value != null) {
            String normalized = value.trim();
            for (Verdict v : values()) {
                // Accept the canonical label ("needs-review"), the enum name ("NEEDS_REVIEW"),
                // and case/separator variants a model may emit over a passthrough provider.
                if (v.json.equalsIgnoreCase(normalized)
                        || v.name().equalsIgnoreCase(normalized)
                        || v.name().equalsIgnoreCase(normalized.replace('-', '_'))) {
                    return v;
                }
            }
        }
        throw new IllegalArgumentException("unknown verdict: " + value);
    }
}
