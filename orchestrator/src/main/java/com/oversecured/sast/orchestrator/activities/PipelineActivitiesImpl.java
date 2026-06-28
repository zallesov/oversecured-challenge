package com.oversecured.sast.orchestrator.activities;

import com.oversecured.sast.common.AndroidPlatform;
import com.oversecured.sast.decompiler.Decompiler;
import com.oversecured.sast.parser.AstIndex;
import com.oversecured.sast.reporter.FindingsMerger;
import com.oversecured.sast.reporter.HtmlReportRenderer;
import com.oversecured.sast.reporter.SarifReportWriter;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

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
    public String decompile(DecompileActivityInput input) {
        Path apk = paths.resolveInputPath(input.apkPath());
        Path sourcesDir = paths.resolveArtifactKey(input.sourcesDirKey());
        apis.decompile(apk, sourcesDir);
        return input.sourcesDirKey();
    }

    @Override
    public String parseSources(ParseActivityInput input) {
        Path sourcesDir = paths.resolveArtifactKey(input.sourcesDirKey());
        Path astIndexDir = paths.resolveArtifactKey(input.astIndexDirKey());
        apis.parse(sourcesDir, astIndexDir);
        return input.astIndexDirKey();
    }

    @Override
    public String extractManifestFacts(ManifestFactsActivityInput input) {
        Path manifestXml = paths.resolveArtifactKey(input.manifestKey());
        Path factsJson = paths.resolveArtifactKey(input.factsKey());
        apis.extractManifestFacts(manifestXml, factsJson);
        return input.factsKey();
    }

    @Override
    public String runTaint(TaintActivityInput input) {
        Path astIndexDir = paths.resolveArtifactKey(input.astIndexDirKey());
        Path factsJson = paths.resolveArtifactKey(input.factsKey());
        Path ruleYaml = paths.resolveArtifactKey(input.rulePath());
        Path findingsJson = paths.resolveArtifactKey(input.findingsKey());
        apis.runTaint(input.analysisName(), astIndexDir, factsJson, ruleYaml, findingsJson);
        return input.findingsKey();
    }

    @Override
    public List<String> runTaintBatch(TaintBatchActivityInput input) {
        Path astIndexDir = paths.resolveArtifactKey(input.astIndexDirKey());
        Path factsJson = paths.resolveArtifactKey(input.factsKey());
        List<TaintRuleSpec> specs = new ArrayList<>();
        List<String> findingsKeys = new ArrayList<>();
        for (TaintBatchActivityInput.Rule rule : input.rules()) {
            specs.add(new TaintRuleSpec(
                    rule.name(),
                    paths.resolveArtifactKey(rule.rulePath()),
                    paths.resolveArtifactKey(rule.findingsKey())));
            findingsKeys.add(rule.findingsKey());
        }
        apis.runTaintBatch(astIndexDir, factsJson, specs);
        return findingsKeys;
    }

    @Override
    public String runManifestMisconfig(MisconfigActivityInput input) {
        Path factsJson = paths.resolveArtifactKey(input.factsKey());
        Path ruleYaml = paths.resolveArtifactKey(input.rulePath());
        Path findingsJson = paths.resolveArtifactKey(input.findingsKey());
        apis.runManifestMisconfig(input.analysisName(), factsJson, ruleYaml, findingsJson);
        return input.findingsKey();
    }

    @Override
    public ReportArtifacts report(ReportActivityInput input) {
        List<Path> findingsFiles = input.findingsKeys().stream()
                .map(paths::resolveArtifactKey)
                .toList();
        Path html = paths.resolveArtifactKey(input.htmlKey());
        Path sarif = paths.resolveArtifactKey(input.sarifKey());
        apis.report(findingsFiles, html, sarif);
        return new ReportArtifacts(input.htmlKey(), input.sarifKey());
    }

    /** One taint rule to run in a batch: its name, resolved rule file, and resolved output file. */
    public record TaintRuleSpec(String name, Path ruleYaml, Path findingsJson) {
    }

    public interface StepApis {
        void decompile(Path apk, Path sourcesDir);

        void parse(Path sourcesDir, Path astIndexDir);

        void extractManifestFacts(Path manifestXml, Path factsJson);

        void runTaint(String analysisName, Path astIndexDir, Path factsJson, Path ruleYaml, Path findingsJson);

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
        public void runTaint(String analysisName, Path astIndexDir, Path factsJson, Path ruleYaml, Path findingsJson) {
            try {
                Object analyzer = new com.oversecured.sast.taint.TaintAnalyzer();
                Method run = analyzer.getClass().getMethod("run", Path.class, Path.class, Path.class, Path.class);
                run.invoke(analyzer, astIndexDir, factsJson, ruleYaml, findingsJson);
            } catch (NoSuchMethodException e) {
                throw new IllegalStateException(
                        "TaintAnalyzer.run(Path astIndexDir, Path factsJson, Path ruleYaml, Path findingsJson)"
                                + " is required for orchestrator production taint activity "
                                + analysisName,
                        e);
            } catch (IllegalAccessException e) {
                throw new IllegalStateException("cannot access TaintAnalyzer.run for " + analysisName, e);
            } catch (InvocationTargetException e) {
                Throwable cause = e.getCause();
                if (cause instanceof RuntimeException runtimeException) {
                    throw runtimeException;
                }
                if (cause instanceof Error error) {
                    throw error;
                }
                throw new IllegalStateException("TaintAnalyzer.run failed for " + analysisName, cause);
            }
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
}
