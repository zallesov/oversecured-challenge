package com.oversecured.sast.aitriage;

import com.oversecured.sast.common.Finding;
import com.oversecured.sast.common.FindingsDoc;
import com.oversecured.sast.common.FlowStep;
import com.oversecured.sast.common.Severity;
import java.util.ArrayList;
import java.util.List;

/**
 * Converts an AI triage result into a standard {@link FindingsDoc} so the verdicts surface as
 * first-class findings (same pipeline as the taint/misconfig analyzers). Only actionable
 * verdicts (exploitable / needs-review) become findings; "safe" verdicts are false positives
 * and are dropped.
 */
public final class TriageFindings {

    public static final String ANALYZER = "ai-triage";

    private TriageFindings() {
    }

    public static FindingsDoc toFindingsDoc(TriageResult result) {
        List<Finding> findings = new ArrayList<>();
        if (result != null && result.items() != null) {
            for (TriageItem item : result.items()) {
                if (item.verdict() == Verdict.SAFE) {
                    continue;
                }
                findings.add(toFinding(item));
            }
        }
        return new FindingsDoc(ANALYZER, findings);
    }

    private static Finding toFinding(TriageItem item) {
        FindingRef ref = item.ref();
        String message = "[" + item.verdict().json() + ", confidence " + item.confidence() + "] "
                + nullToEmpty(item.rationale());

        List<String> notes = new ArrayList<>();
        if (item.fix() != null && !item.fix().isBlank()) {
            notes.add("Fix: " + item.fix());
        }
        if (item.references() != null) {
            notes.addAll(item.references());
        }

        return new Finding(
                ref.ruleId(),
                "AI Triage: " + item.verdict().json(),
                severityOf(item.severity()),
                message,
                cweFrom(item.references()),
                owaspFrom(item.references()),
                List.of(new FlowStep(ref.file(), ref.line(), "source")),
                notes);
    }

    /** Map the triage severity vocabulary onto the SARIF-aligned Severity enum. */
    private static Severity severityOf(TriageSeverity severity) {
        if (severity == null) {
            return Severity.WARNING;
        }
        return switch (severity) {
            case CRITICAL, HIGH -> Severity.ERROR;
            case MEDIUM -> Severity.WARNING;
            case LOW, INFO -> Severity.NOTE;
        };
    }

    private static String cweFrom(List<String> references) {
        return firstMatching(references, "CWE-");
    }

    private static String owaspFrom(List<String> references) {
        if (references == null) {
            return null;
        }
        for (String ref : references) {
            if (ref != null && ref.matches("M\\d+.*")) {
                return ref;
            }
        }
        return null;
    }

    private static String firstMatching(List<String> references, String prefix) {
        if (references == null) {
            return null;
        }
        for (String ref : references) {
            if (ref != null && ref.startsWith(prefix)) {
                return ref;
            }
        }
        return null;
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }
}
