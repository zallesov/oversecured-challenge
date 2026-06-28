package com.oversecured.sast.aitriage;

import com.oversecured.sast.common.Finding;
import com.oversecured.sast.common.FindingsDoc;
import com.oversecured.sast.common.FlowStep;
import com.oversecured.sast.common.Json;
import com.oversecured.sast.common.Severity;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Converts an AI triage result into a standard {@link FindingsDoc} so the verdicts surface as
 * first-class findings (same pipeline as the taint/misconfig analyzers). Only actionable
 * verdicts (exploitable / needs-review) become findings; "safe" verdicts are false positives
 * and are dropped.
 *
 * <p>{@link #toJson} additionally embeds the triage-specific fields (verdict, confidence, fix)
 * on each finding so the UI can render them as dedicated columns. Those extra fields are
 * preserved verbatim in the finding's {@code raw_json} and ignored by the strict Java schema.
 */
public final class TriageFindings {

    public static final String ANALYZER = "ai-triage";

    private TriageFindings() {
    }

    private static List<TriageItem> actionable(TriageResult result) {
        List<TriageItem> items = new ArrayList<>();
        if (result != null && result.items() != null) {
            for (TriageItem item : result.items()) {
                if (item.verdict() != Verdict.SAFE) {
                    items.add(item);
                }
            }
        }
        return items;
    }

    /** Strict common-schema view — drives findingCount and the DB column mapping. */
    public static FindingsDoc toFindingsDoc(TriageResult result) {
        List<Finding> findings = new ArrayList<>();
        for (TriageItem item : actionable(result)) {
            FindingRef ref = item.ref();
            findings.add(new Finding(
                    ref.ruleId(),
                    "AI Triage: " + item.verdict().json(),
                    severityOf(item.severity()),
                    message(item),
                    cweFrom(item.references()),
                    owaspFrom(item.references()),
                    List.of(new FlowStep(ref.file(), ref.line(), "source")),
                    notes(item)));
        }
        return new FindingsDoc(ANALYZER, findings);
    }

    /** Enriched JSON written to disk: common fields + verdict/confidence/fix for the UI. */
    public static String toJson(TriageResult result) {
        List<Map<String, Object>> findings = new ArrayList<>();
        for (TriageItem item : actionable(result)) {
            FindingRef ref = item.ref();
            Map<String, Object> f = new LinkedHashMap<>();
            f.put("ruleId", ref.ruleId());
            f.put("vulnerabilityClass", "AI Triage: " + item.verdict().json());
            f.put("severity", severityOf(item.severity()).name());
            f.put("message", message(item));
            f.put("cwe", cweFrom(item.references()));
            f.put("owaspMobile", owaspFrom(item.references()));
            f.put("flow", List.of(Map.of("file", ref.file(), "line", ref.line(), "label", "source")));
            f.put("notes", notes(item));
            // Triage-specific extras (surfaced as UI columns; ignored by the strict Java schema).
            f.put("verdict", item.verdict().json());
            f.put("confidence", item.confidence());
            f.put("fix", item.fix());
            findings.add(f);
        }
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("analyzer", ANALYZER);
        doc.put("findings", findings);
        return Json.writeString(doc);
    }

    private static String message(TriageItem item) {
        return "[" + item.verdict().json() + ", confidence " + item.confidence() + "] "
                + nullToEmpty(item.rationale());
    }

    private static List<String> notes(TriageItem item) {
        List<String> notes = new ArrayList<>();
        if (item.fix() != null && !item.fix().isBlank()) {
            notes.add("Fix: " + item.fix());
        }
        if (item.references() != null) {
            notes.addAll(item.references());
        }
        return notes;
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
