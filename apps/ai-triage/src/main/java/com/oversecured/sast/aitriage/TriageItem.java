package com.oversecured.sast.aitriage;

import java.util.List;

public record TriageItem(
        FindingRef ref,
        Verdict verdict,
        TriageSeverity severity,
        double confidence,
        String rationale,
        String fix,
        List<String> references) {
}
