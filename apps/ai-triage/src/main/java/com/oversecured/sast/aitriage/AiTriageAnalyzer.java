package com.oversecured.sast.aitriage;

import com.oversecured.sast.common.FindingsDoc;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

/** Always-on, fail-soft AI triage step. Never throws; always writes both sidecar files. */
public final class AiTriageAnalyzer {

    private final TriageEngineFactory factory;

    public AiTriageAnalyzer() {
        this(defaultFactory());
    }

    public AiTriageAnalyzer(TriageEngineFactory factory) {
        this.factory = factory;
    }

    /** Outcome of a triage run. Never an exception — the step is fail-soft. */
    public enum Status {
        /** The engine ran and produced a verdict for at least one finding. */
        OK,
        /** Benign skip: no API key configured, or no findings to triage. */
        SKIPPED,
        /** The engine was available but failed (API/parse/tool error). The sidecar explains why. */
        ERROR
    }

    public record Result(Status status, String message, int findingCount) {
    }

    /**
     * Always writes the sidecar files ({@code outJson}, {@code outMd}) plus a standard
     * {@link FindingsDoc} ({@code outFindings}) so actionable verdicts surface as findings.
     * Returns an outcome; never throws.
     */
    public Result run(Path sarif, Path sourcesDir, Path outJson, Path outMd, Path outFindings) {
        TriageResult result;
        Status status;
        String message;
        try {
            List<TriageFinding> findings = new SarifFindings().parse(sarif);
            TriageEngine engine = factory.create(sourcesDir);
            if (engine == null) {
                result = empty("AI triage skipped: no engine available (set OPENROUTER_API_KEY).");
                status = Status.SKIPPED;
            } else if (findings.isEmpty()) {
                result = empty("AI triage skipped: no findings to analyze.");
                status = Status.SKIPPED;
            } else {
                result = engine.triage(findings);
                status = Status.OK;
            }
        } catch (Exception e) {
            result = empty("AI triage failed: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            status = Status.ERROR;
        }

        FindingsDoc findingsDoc = TriageFindings.toFindingsDoc(result);
        int findingCount = findingsDoc.findings().size();
        if (status == Status.OK) {
            message = "AI triage analyzed " + result.items().size() + " findings ("
                    + findingCount + " actionable).";
        } else {
            message = result.summary();
        }

        writeSoft(outJson, TriageJson.write(result));
        writeSoft(outMd, MarkdownRenderer.render(result));
        writeSoft(outFindings, TriageFindings.toJson(result));
        return new Result(status, message, findingCount);
    }

    private TriageResult empty(String summary) {
        return new TriageResult(null, Instant.now().toString(), summary, List.of());
    }

    private void writeSoft(Path path, String content) {
        try {
            if (path.getParent() != null) {
                Files.createDirectories(path.getParent());
            }
            Files.writeString(path, content);
        } catch (IOException e) {
            // Last-resort: cannot write the sidecar. Swallow — the step must not break the pipeline.
            System.err.println("ai-triage: failed to write " + path + ": " + e.getMessage());
        }
    }

    private static TriageEngineFactory defaultFactory() {
        String model = System.getenv().getOrDefault("OPENROUTER_MODEL", "anthropic/claude-haiku-4.5");
        return sourcesDir -> LangChainTriageEngine.create(
                System.getenv("OPENROUTER_API_KEY"),
                "https://openrouter.ai/api/v1",
                model,
                sourcesDir);
    }
}
