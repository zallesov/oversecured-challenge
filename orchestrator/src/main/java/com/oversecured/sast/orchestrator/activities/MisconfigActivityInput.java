package com.oversecured.sast.orchestrator.activities;

public record MisconfigActivityInput(
        String analysisName,
        String factsKey,
        String rulePath,
        String findingsKey) {
}
