package com.oversecured.sast.reporter;

import static com.oversecured.sast.reporter.HtmlEscaper.escape;

import com.oversecured.sast.common.Finding;
import com.oversecured.sast.common.FlowStep;
import com.oversecured.sast.common.Severity;
import java.util.List;

/** Renders merged findings into a single static HTML document. */
public final class HtmlReportRenderer {

    public String render(List<Finding> findings) {
        StringBuilder b = new StringBuilder();
        b.append("<!DOCTYPE html>\n");
        b.append("<html lang=\"en\"><head><meta charset=\"utf-8\">");
        b.append("<title>Android Taint SAST Report</title>");
        b.append("<style>")
                .append("body{font-family:system-ui,sans-serif;margin:2rem;line-height:1.45;}")
                .append(".finding{border:1px solid #ccc;border-radius:6px;padding:1rem;margin:1rem 0;}")
                .append(".sev-ERROR{border-left:6px solid #c0392b;}")
                .append(".sev-WARNING{border-left:6px solid #d68910;}")
                .append(".sev-NOTE{border-left:6px solid #2980b9;}")
                .append("code{background:#f4f4f4;padding:0 .25rem;}")
                .append("</style></head><body>");
        b.append("<h1>Android Taint SAST Report</h1>");

        if (findings.isEmpty()) {
            b.append("<p>No findings.</p>");
        } else {
            for (Severity severity : Severity.values()) {
                List<Finding> group = findings.stream().filter(f -> f.severity() == severity).toList();
                if (group.isEmpty()) {
                    continue;
                }
                b.append("<section><h2>").append(severity.name())
                        .append(" (").append(group.size()).append(")</h2>");
                for (Finding finding : group) {
                    renderFinding(b, finding);
                }
                b.append("</section>");
            }
        }

        b.append("</body></html>");
        return b.toString();
    }

    private void renderFinding(StringBuilder b, Finding f) {
        b.append("<div class=\"finding sev-").append(escape(f.severity().name())).append("\">");
        b.append("<h3>").append(escape(f.ruleId())).append("</h3>");
        b.append("<p>").append(escape(f.message())).append("</p>");
        b.append("<p><strong>Class:</strong> ").append(escape(f.vulnerabilityClass()))
                .append(" &middot; <strong>").append(escape(f.cwe())).append("</strong>")
                .append(" &middot; OWASP ").append(escape(f.owaspMobile())).append("</p>");

        if (f.flow() != null && !f.flow().isEmpty()) {
            b.append("<h4>Source &rarr; sink flow</h4><ol>");
            for (FlowStep step : f.flow()) {
                b.append("<li>").append(escape(step.label()))
                        .append(" &mdash; <code>")
                        .append(escape(step.file())).append(":").append(step.line())
                        .append("</code></li>");
            }
            b.append("</ol>");
        }

        if (f.notes() != null && !f.notes().isEmpty()) {
            b.append("<h4>Notes</h4><ul>");
            for (String note : f.notes()) {
                b.append("<li>").append(escape(note)).append("</li>");
            }
            b.append("</ul>");
        }

        b.append("</div>");
    }
}
