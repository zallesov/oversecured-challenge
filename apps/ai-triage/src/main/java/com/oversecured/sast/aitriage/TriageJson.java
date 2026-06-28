package com.oversecured.sast.aitriage;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public final class TriageJson {

    private static final ObjectMapper MAPPER = new ObjectMapper();

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
