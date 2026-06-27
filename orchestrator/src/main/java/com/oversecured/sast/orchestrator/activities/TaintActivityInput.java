package com.oversecured.sast.orchestrator.activities;

public record TaintActivityInput(
        String analysisName,
        String astIndexDirKey,
        String factsKey,
        String rulePath,
        String findingsKey) {
}
