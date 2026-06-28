package com.oversecured.sast.orchestrator.activities;

import com.oversecured.sast.common.AndroidPlatform;
import com.oversecured.sast.common.Finding;
import com.oversecured.sast.common.FindingsDoc;
import com.oversecured.sast.common.Json;
import com.oversecured.sast.common.PipelineException;
import com.oversecured.sast.common.Severity;
import com.oversecured.sast.decompiler.Decompiler;
import com.oversecured.sast.orchestrator.status.ArtifactRef;
import com.oversecured.sast.orchestrator.status.StepResult;
import com.oversecured.sast.parser.AstIndex;
import com.oversecured.sast.reporter.FindingsMerger;
import com.oversecured.sast.reporter.HtmlReportRenderer;
import com.oversecured.sast.reporter.SarifReportWriter;
import io.temporal.failure.ApplicationFailure;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

public final class PipelineActivitiesImpl implements PipelineActivities {

    private final ActivityPathResolver paths;
    private final StepApis apis;

    public PipelineActivitiesImpl(Path artifactRoot) {
        this(artifactRoot, new ProductionStepApis());
    }

    private PipelineActivitiesImpl(Path artifactRoot, StepApis apis) {
        this.paths = new ActivityPathResolver(artifactRoot);
        this.apis = apis;
    }

    public static PipelineActivitiesImpl forTesting(Path artifactRoot, StepApis apis) {
        return new PipelineActivitiesImpl(artifactRoot, apis);
    }

    @Override
    public StepResult decompile(DecompileActivityInput input) {
        return withPipelineFailureBoundary(() -> {
            Path apk = paths.resolveInputPath(input.apkPath());
            Path sourcesDir = paths.resolveArtifactKey(input.sourcesDirKey());
            apis.decompile(apk, sourcesDir);
            int sourceFileCount = countSourceFiles(sourcesDir);
            return StepResult.completed(
                    "decompile",
                    "Decompiled APK into " + sourceFileCount + " source files.",
                    Map.of("sourceFileCount", sourceFileCount),
                    List.of(
                            new ArtifactRef("sources", input.sourcesDirKey()),
                            new ArtifactRef("manifest", input.manifestKey())),
                    List.of(),
                    0,
                    Map.of());
        });
    }

    @Override
    public StepResult parseSources(ParseActivityInput input) {
        return withPipelineFailureBoundary(() -> {
            Path sourcesDir = paths.resolveArtifactKey(input.sourcesDirKey());
            Path astIndexDir = paths.resolveArtifactKey(input.astIndexDirKey());
            apis.parse(sourcesDir, astIndexDir);
            int indexFileCount = countRegularFiles(astIndexDir);
            return StepResult.completed(
                    "parse",
                    "Parsed sources and wrote AST index.",
                    Map.of("indexFileCount", indexFileCount),
                    List.of(new ArtifactRef("ast-index", input.astIndexDirKey())),
                    List.of(),
                    0,
                    Map.of());
        });
    }

    @Override
    public StepResult extractManifestFacts(ManifestFactsActivityInput input) {
        return withPipelineFailureBoundary(() -> {
            Path manifestXml = paths.resolveArtifactKey(input.manifestKey());
            Path factsJson = paths.resolveArtifactKey(input.factsKey());
            apis.extractManifestFacts(manifestXml, factsJson);
            return StepResult.completed(
                    "manifest-facts",
                    "Extracted manifest facts.",
                    Map.of("factsWritten", Files.exists(factsJson)),
                    List.of(new ArtifactRef("facts", input.factsKey())),
                    List.of(),
                    0,
                    Map.of());
        });
    }

    @Override
    public StepResult runTaintBatch(TaintBatchActivityInput input) {
        return withPipelineFailureBoundary(() -> {
            Path astIndexDir = paths.resolveArtifactKey(input.astIndexDirKey());
            Path factsJson = paths.resolveArtifactKey(input.factsKey());
            List<TaintRuleSpec> specs = new ArrayList<>();
            List<String> findingsKeys = new ArrayList<>();
            List<ArtifactRef> artifacts = new ArrayList<>();
            for (TaintBatchActivityInput.Rule rule : input.rules()) {
                specs.add(new TaintRuleSpec(
                        rule.name(),
                        paths.resolveArtifactKey(rule.rulePath()),
                        paths.resolveArtifactKey(rule.findingsKey())));
                findingsKeys.add(rule.findingsKey());
                artifacts.add(new ArtifactRef("findings", rule.findingsKey()));
            }
            apis.runTaintBatch(astIndexDir, factsJson, specs);

            List<Map<String, Object>> ruleMetrics = new ArrayList<>();
            int findingCount = 0;
            Map<Severity, Integer> severityCounts = new EnumMap<>(Severity.class);
            for (int i = 0; i < specs.size(); i++) {
                FindingSummary summary = summarizeFindings(specs.get(i).findingsJson());
                findingCount += summary.findingCount();
                mergeSeverityCounts(severityCounts, summary.severityCounts());
                ruleMetrics.add(Map.of(
                        "rule", input.rules().get(i).name(),
                        "findingCount", summary.findingCount()));
            }

            Map<String, Object> metrics = new LinkedHashMap<>();
            metrics.put("ruleCount", input.rules().size());
            metrics.put("rules", ruleMetrics);
            return StepResult.completed(
                    "taint",
                    "Completed taint analysis for " + input.rules().size() + " rules with " + findingCount + " findings.",
                    metrics,
                    artifacts,
                    findingsKeys,
                    findingCount,
                    severityCounts);
        });
    }

    @Override
    public StepResult runManifestMisconfig(MisconfigActivityInput input) {
        return withPipelineFailureBoundary(() -> {
            Path factsJson = paths.resolveArtifactKey(input.factsKey());
            Path ruleYaml = paths.resolveArtifactKey(input.rulePath());
            Path findingsJson = paths.resolveArtifactKey(input.findingsKey());
            apis.runManifestMisconfig(input.analysisName(), factsJson, ruleYaml, findingsJson);
            FindingSummary summary = summarizeFindings(findingsJson);
            return StepResult.completed(
                    "manifest-misconfig",
                    "Completed manifest misconfiguration analysis with " + summary.findingCount() + " findings.",
                    Map.of(),
                    List.of(new ArtifactRef("findings", input.findingsKey())),
                    List.of(input.findingsKey()),
                    summary.findingCount(),
                    summary.severityCounts());
        });
    }

    @Override
    public StepResult report(ReportActivityInput input) {
        return withPipelineFailureBoundary(() -> {
            List<Path> findingsFiles = input.findingsKeys().stream()
                    .map(paths::resolveArtifactKey)
                    .toList();
            Path html = paths.resolveArtifactKey(input.htmlKey());
            Path sarif = paths.resolveArtifactKey(input.sarifKey());
            apis.report(findingsFiles, html, sarif);
            return StepResult.completed(
                    "report",
                    "Generated HTML and SARIF reports.",
                    Map.of(
                            "htmlWritten", Files.exists(html),
                            "sarifWritten", Files.exists(sarif)),
                    List.of(
                            new ArtifactRef("html", input.htmlKey()),
                            new ArtifactRef("sarif", input.sarifKey())),
                    List.of(),
                    0,
                    Map.of());
        });
    }

    /** One taint rule to run in a batch: its name, resolved rule file, and resolved output file. */
    public record TaintRuleSpec(String name, Path ruleYaml, Path findingsJson) {
    }

    public interface StepApis {
        void decompile(Path apk, Path sourcesDir);

        void parse(Path sourcesDir, Path astIndexDir);

        void extractManifestFacts(Path manifestXml, Path factsJson);

        void runTaintBatch(Path astIndexDir, Path factsJson, List<TaintRuleSpec> rules);

        void runManifestMisconfig(String analysisName, Path factsJson, Path ruleYaml, Path findingsJson);

        void report(List<Path> findingsFiles, Path html, Path sarif);
    }

    private static final class ProductionStepApis implements StepApis {
        @Override
        public void decompile(Path apk, Path sourcesDir) {
            new Decompiler().decompile(apk, sourcesDir);
        }

        @Override
        public void parse(Path sourcesDir, Path astIndexDir) {
            // Default the resolution classpath to the Android SDK android.jar so framework calls
            // (WebView.loadUrl, Intent.getStringExtra) resolve on a decompiled APK; without it the
            // taint signature matcher matches nothing. Fail-soft: empty when no SDK is found.
            AstIndex.build(sourcesDir, AndroidPlatform.resolve()).save(astIndexDir);
        }

        @Override
        public void extractManifestFacts(Path manifestXml, Path factsJson) {
            new com.oversecured.sast.manifestfacts.ManifestFactsApp()
                    .extract(manifestXml, factsJson);
        }

        @Override
        public void runTaintBatch(Path astIndexDir, Path factsJson, List<TaintRuleSpec> rules) {
            List<com.oversecured.sast.taint.TaintAnalyzer.RuleRun> runs = new ArrayList<>();
            for (TaintRuleSpec spec : rules) {
                runs.add(new com.oversecured.sast.taint.TaintAnalyzer.RuleRun(spec.ruleYaml(), spec.findingsJson()));
            }
            new com.oversecured.sast.taint.TaintAnalyzer().runBatch(astIndexDir, factsJson, runs);
        }

        @Override
        public void runManifestMisconfig(String analysisName, Path factsJson, Path ruleYaml, Path findingsJson) {
            try {
                new com.oversecured.sast.misconfig.MisconfigApp()
                        .analyze(factsJson, ruleYaml, findingsJson);
            } catch (IOException e) {
                throw new UncheckedIOException("manifest misconfig analysis failed for " + analysisName, e);
            }
        }

        @Override
        public void report(List<Path> findingsFiles, Path html, Path sarif) {
            try {
                Path htmlParent = html.getParent();
                if (htmlParent != null) {
                    Files.createDirectories(htmlParent);
                }
                Path sarifParent = sarif.getParent();
                if (sarifParent != null) {
                    Files.createDirectories(sarifParent);
                }
                var findings = new FindingsMerger().merge(findingsFiles);
                Files.writeString(html, new HtmlReportRenderer().render(findings));
                Files.writeString(sarif, new SarifReportWriter().toSarifJson(findings));
            } catch (IOException e) {
                throw new UncheckedIOException("failed to write reports", e);
            }
        }
    }

    private static int countSourceFiles(Path sourcesDir) {
        if (!Files.exists(sourcesDir)) {
            return 0;
        }
        try (Stream<Path> stream = Files.walk(sourcesDir)) {
            return (int) stream
                    .filter(Files::isRegularFile)
                    .filter(path -> path.getFileName().toString().endsWith(".java"))
                    .count();
        } catch (IOException e) {
            throw new UncheckedIOException("failed to count source files in " + sourcesDir, e);
        }
    }

    private static int countRegularFiles(Path dir) {
        if (!Files.exists(dir)) {
            return 0;
        }
        try (Stream<Path> stream = Files.walk(dir)) {
            return (int) stream.filter(Files::isRegularFile).count();
        } catch (IOException e) {
            throw new UncheckedIOException("failed to count files in " + dir, e);
        }
    }

    private static FindingSummary summarizeFindings(Path findingsJson) {
        FindingsDoc doc;
        try {
            doc = Json.read(Files.readAllBytes(findingsJson), FindingsDoc.class);
        } catch (IOException e) {
            throw new UncheckedIOException("failed to read findings file " + findingsJson, e);
        }
        List<Finding> findings = doc.findings() == null ? List.of() : doc.findings();
        Map<Severity, Integer> severityCounts = new EnumMap<>(Severity.class);
        for (Finding finding : findings) {
            if (finding.severity() != null) {
                severityCounts.merge(finding.severity(), 1, Integer::sum);
            }
        }
        return new FindingSummary(findings.size(), severityCounts);
    }

    private static void mergeSeverityCounts(Map<Severity, Integer> target, Map<Severity, Integer> source) {
        for (Map.Entry<Severity, Integer> entry : source.entrySet()) {
            target.merge(entry.getKey(), entry.getValue(), Integer::sum);
        }
    }

    private static StepResult withPipelineFailureBoundary(ActivityStep step) {
        try {
            return step.run();
        } catch (PipelineException e) {
            if (e.kind() == com.oversecured.sast.common.FailureKind.PERMANENT) {
                throw ApplicationFailure.newNonRetryableFailure(e.getMessage(), e.kind().name());
            }
            throw ApplicationFailure.newFailure(e.getMessage(), e.kind().name());
        }
    }

    @FunctionalInterface
    private interface ActivityStep {
        StepResult run();
    }

    private record FindingSummary(int findingCount, Map<Severity, Integer> severityCounts) {
    }
}
