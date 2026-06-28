package com.oversecured.sast.aitriage;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

public final class TriageJson {

    // Models over a passthrough provider may add unknown keys; ignore them rather than fail.
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

    private TriageJson() {
    }

    public static String write(TriageResult result) {
        try {
            return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(result);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("failed to serialize triage result", e);
        }
    }

    public static TriageResult read(String json) {
        try {
            return MAPPER.readValue(json, TriageResult.class);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("failed to deserialize triage result", e);
        }
    }
}
