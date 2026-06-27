package com.oversecured.sast.common;

import java.util.List;

/** One vulnerability finding, analyzer-agnostic (spec §7). */
public record Finding(
        String ruleId,
        String vulnerabilityClass,
        Severity severity,
        String message,
        String cwe,
        String owaspMobile,
        List<FlowStep> flow,
        List<String> notes) {
}
