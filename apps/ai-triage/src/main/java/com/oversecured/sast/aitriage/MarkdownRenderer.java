package com.oversecured.sast.aitriage;

public final class MarkdownRenderer {

    private MarkdownRenderer() {
    }

    public static String render(TriageResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append("# AI Triage\n\n");
        sb.append("_Model: ").append(result.model())
                .append(" — generated ").append(result.generatedAt()).append("_\n\n");
        sb.append(result.summary()).append("\n");
        for (TriageItem item : result.items()) {
            FindingRef ref = item.ref();
            sb.append("\n## ").append(ref.ruleId())
                    .append(" (").append(ref.file()).append(":").append(ref.line()).append(")\n\n");
            sb.append("- **Verdict:** ").append(item.verdict().json()).append("\n");
            sb.append("- **Severity:** ").append(item.severity().json()).append("\n");
            sb.append("- **Confidence:** ").append(item.confidence()).append("\n");
            sb.append("- **Rationale:** ").append(item.rationale()).append("\n");
            sb.append("- **Fix:** ").append(item.fix()).append("\n");
            if (item.references() != null && !item.references().isEmpty()) {
                sb.append("- **References:** ").append(String.join(", ", item.references())).append("\n");
            }
        }
        return sb.toString();
    }
}
