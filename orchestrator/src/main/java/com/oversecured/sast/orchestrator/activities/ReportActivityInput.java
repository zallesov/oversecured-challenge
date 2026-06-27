package com.oversecured.sast.orchestrator.activities;

import java.util.List;

public record ReportActivityInput(List<String> findingsKeys, String htmlKey, String sarifKey) {
    public ReportActivityInput {
        findingsKeys = List.copyOf(findingsKeys);
    }
}
