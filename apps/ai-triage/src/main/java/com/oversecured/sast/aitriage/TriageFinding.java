package com.oversecured.sast.aitriage;

import java.util.List;

public record TriageFinding(
        String ruleId,
        String level,
        String message,
        String cwe,
        String owaspMobile,
        List<TriageFlowStep> flow,
        FindingRef ref) {
}
