package com.oversecured.sast.orchestrator.activities;

public record AiTriageActivityInput(
        String sarifKey,
        String sourcesDirKey,
        String outJsonKey,
        String outMdKey,
        String outFindingsKey) {
}
