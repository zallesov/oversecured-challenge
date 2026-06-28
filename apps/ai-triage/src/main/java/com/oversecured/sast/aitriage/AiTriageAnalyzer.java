package com.oversecured.sast.aitriage;

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

    public void run(Path sarif, Path sourcesDir, Path outJson, Path outMd) {
        TriageResult result;
        try {
            List<TriageFinding> findings = new SarifFindings().parse(sarif);
            TriageEngine engine = factory.create(sourcesDir);
            if (engine == null) {
                result = empty("AI triage skipped: no engine available (set OPENROUTER_API_KEY).");
            } else if (findings.isEmpty()) {
                result = empty("AI triage skipped: no findings to analyze.");
            } else {
                result = engine.triage(findings);
            }
        } catch (Exception e) {
            result = empty("AI triage skipped: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        writeSoft(outJson, TriageJson.write(result));
        writeSoft(outMd, MarkdownRenderer.render(result));
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
