package com.oversecured.sast.orchestrator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.oversecured.sast.common.Finding;
import com.oversecured.sast.common.FindingsDoc;
import com.oversecured.sast.common.FailureKind;
import com.oversecured.sast.common.Json;
import com.oversecured.sast.common.PipelineException;
import com.oversecured.sast.common.Severity;
import com.oversecured.sast.orchestrator.activities.DecompileActivityInput;
import com.oversecured.sast.orchestrator.activities.ManifestFactsActivityInput;
import com.oversecured.sast.orchestrator.activities.MisconfigActivityInput;
import com.oversecured.sast.orchestrator.activities.ParseActivityInput;
import com.oversecured.sast.orchestrator.activities.PipelineActivitiesImpl;
import com.oversecured.sast.orchestrator.activities.ReportActivityInput;
import com.oversecured.sast.orchestrator.activities.TaintBatchActivityInput;
import com.oversecured.sast.orchestrator.status.ArtifactRef;
import com.oversecured.sast.orchestrator.status.StepResult;
import io.temporal.failure.ApplicationFailure;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PipelineActivitiesImplTest {

    @Test
    void decompileReturnsMessageArtifactsAndSourceFileCountMetric(@TempDir Path root) throws Exception {
        RecordingStepApis apis = new RecordingStepApis();
        PipelineActivitiesImpl activities = PipelineActivitiesImpl.forTesting(root, apis);
        Files.writeString(root.resolve("apk.apk"), "fake-apk");

        StepResult result = activities.decompile(new DecompileActivityInput(
                root.resolve("apk.apk").toString(),
                "runs/r1/sources",
                "runs/r1/sources/AndroidManifest.xml"));

        assertThat(result.nodeId()).isEqualTo("decompile");
        assertThat(result.message()).isEqualTo("Decompiled APK into 2 source files.");
        assertThat(result.metrics()).containsEntry("sourceFileCount", 2);
        assertThat(result.artifacts()).containsExactly(
                new ArtifactRef("sources", "runs/r1/sources"),
                new ArtifactRef("manifest", "runs/r1/sources/AndroidManifest.xml"));
        assertThat(result.findingsKeys()).isEmpty();
        assertThat(result.findingCount()).isZero();
        assertThat(apis.calls).containsExactly(
                "decompile:" + root.resolve("apk.apk").toAbsolutePath().normalize() + "->" + root.resolve("runs/r1/sources").toAbsolutePath().normalize());
    }

    @Test
    void activitiesResolveKeysAndReturnRequestedStepResults(@TempDir Path root) throws Exception {
        RecordingStepApis apis = new RecordingStepApis();
        PipelineActivitiesImpl activities = PipelineActivitiesImpl.forTesting(root, apis);
        Files.writeString(root.resolve("apk.apk"), "fake-apk");

        StepResult sources = activities.decompile(new DecompileActivityInput(
                root.resolve("apk.apk").toString(),
                "runs/r1/sources",
                "runs/r1/sources/AndroidManifest.xml"));
        StepResult ast = activities.parseSources(new ParseActivityInput(
                "runs/r1/sources",
                "runs/r1/ast-index"));
        StepResult facts = activities.extractManifestFacts(new ManifestFactsActivityInput(
                "runs/r1/sources/AndroidManifest.xml",
                "runs/r1/facts.json"));
        StepResult taint = activities.runTaintBatch(new TaintBatchActivityInput(
                "runs/r1/ast-index",
                "runs/r1/facts.json",
                List.of(new TaintBatchActivityInput.Rule(
                        "webview",
                        "rules/webview.yaml",
                        "runs/r1/findings-webview.json"))));
        StepResult misconfig = activities.runManifestMisconfig(new MisconfigActivityInput(
                "manifest-misconfig",
                "runs/r1/facts.json",
                "rules/misconfig.yaml",
                "runs/r1/findings-misconfig.json"));
        StepResult reports = activities.report(new ReportActivityInput(
                List.of("runs/r1/findings-webview.json", "runs/r1/findings-misconfig.json"),
                "runs/r1/report.html",
                "runs/r1/report.sarif"));

        assertThat(sources.artifacts()).contains(new ArtifactRef("sources", "runs/r1/sources"));
        assertThat(ast.artifacts()).containsExactly(new ArtifactRef("ast-index", "runs/r1/ast-index"));
        assertThat(facts.artifacts()).containsExactly(new ArtifactRef("facts", "runs/r1/facts.json"));
        assertThat(taint.findingsKeys()).containsExactly("runs/r1/findings-webview.json");
        assertThat(misconfig.findingsKeys()).containsExactly("runs/r1/findings-misconfig.json");
        assertThat(reports.artifacts()).containsExactly(
                new ArtifactRef("html", "runs/r1/report.html"),
                new ArtifactRef("sarif", "runs/r1/report.sarif"));

        assertThat(apis.calls).containsExactly(
                "decompile:" + root.resolve("apk.apk").toAbsolutePath().normalize() + "->" + root.resolve("runs/r1/sources").toAbsolutePath().normalize(),
                "parse:" + root.resolve("runs/r1/sources").toAbsolutePath().normalize() + "->" + root.resolve("runs/r1/ast-index").toAbsolutePath().normalize(),
                "mfacts:" + root.resolve("runs/r1/sources/AndroidManifest.xml").toAbsolutePath().normalize() + "->" + root.resolve("runs/r1/facts.json").toAbsolutePath().normalize(),
                "taint-batch:" + root.resolve("runs/r1/ast-index").toAbsolutePath().normalize()
                        + ";webview:" + root.resolve("rules/webview.yaml").toAbsolutePath().normalize()
                        + "->" + root.resolve("runs/r1/findings-webview.json").toAbsolutePath().normalize(),
                "misconfig:manifest-misconfig:" + root.resolve("rules/misconfig.yaml").toAbsolutePath().normalize() + "->" + root.resolve("runs/r1/findings-misconfig.json").toAbsolutePath().normalize(),
                "report:2->" + root.resolve("runs/r1/report.html").toAbsolutePath().normalize() + ":" + root.resolve("runs/r1/report.sarif").toAbsolutePath().normalize());
    }

    @Test
    void runTaintBatchResolvesAllRulesFromOneCallAndReturnsAggregatedTelemetry(@TempDir Path root) {
        RecordingStepApis apis = new RecordingStepApis();
        PipelineActivitiesImpl activities = PipelineActivitiesImpl.forTesting(root, apis);

        StepResult result = activities.runTaintBatch(new TaintBatchActivityInput(
                "runs/r1/ast-index",
                "runs/r1/facts.json",
                List.of(
                        new TaintBatchActivityInput.Rule("webview", "rules/webview.yaml", "runs/r1/findings-webview.json"),
                        new TaintBatchActivityInput.Rule("pathtraversal", "rules/pathtraversal.yaml", "runs/r1/findings-pathtraversal.json"))));

        assertThat(result.nodeId()).isEqualTo("taint");
        assertThat(result.message()).isEqualTo("Completed taint analysis for 2 rules with 3 findings.");
        assertThat(result.findingsKeys()).containsExactly(
                "runs/r1/findings-webview.json",
                "runs/r1/findings-pathtraversal.json");
        assertThat(result.findingCount()).isEqualTo(3);
        assertThat(result.severityCounts()).containsEntry(Severity.ERROR, 1);
        assertThat(result.severityCounts()).containsEntry(Severity.WARNING, 2);
        assertThat(result.metrics()).containsEntry("ruleCount", 2);
        assertThat(result.metrics()).containsEntry("rules", List.of(
                Map.of("rule", "webview", "findingCount", 2),
                Map.of("rule", "pathtraversal", "findingCount", 1)));
        assertThat(result.artifacts()).containsExactly(
                new ArtifactRef("findings", "runs/r1/findings-webview.json"),
                new ArtifactRef("findings", "runs/r1/findings-pathtraversal.json"));
        assertThat(apis.calls).containsExactly(
                "taint-batch:" + root.resolve("runs/r1/ast-index").toAbsolutePath().normalize()
                        + ";webview:" + root.resolve("rules/webview.yaml").toAbsolutePath().normalize()
                        + "->" + root.resolve("runs/r1/findings-webview.json").toAbsolutePath().normalize()
                        + ";pathtraversal:" + root.resolve("rules/pathtraversal.yaml").toAbsolutePath().normalize()
                        + "->" + root.resolve("runs/r1/findings-pathtraversal.json").toAbsolutePath().normalize());
    }

    @Test
    void aiTriageResolvesKeysAndReturnsArtifacts(@TempDir Path root) {
        RecordingStepApis apis = new RecordingStepApis();
        PipelineActivitiesImpl activities = PipelineActivitiesImpl.forTesting(root, apis);

        StepResult result = activities.aiTriage(new com.oversecured.sast.orchestrator.activities.AiTriageActivityInput(
                "runs/r1/report.sarif",
                "runs/r1/sources",
                "runs/r1/ai-triage.json",
                "runs/r1/ai-triage.md",
                "runs/r1/findings-ai-triage.json"));

        assertThat(result.nodeId()).isEqualTo("ai-triage");
        assertThat(result.artifacts()).containsExactly(
                new ArtifactRef("ai-triage-json", "runs/r1/ai-triage.json"),
                new ArtifactRef("ai-triage-md", "runs/r1/ai-triage.md"),
                new ArtifactRef("findings", "runs/r1/findings-ai-triage.json"));
        // Actionable verdicts are surfaced as findings for UI ingestion.
        assertThat(result.findingsKeys()).containsExactly("runs/r1/findings-ai-triage.json");
        assertThat(result.findingCount()).isEqualTo(1);
        assertThat(apis.calls).containsExactly(
                "aitriage:" + root.resolve("runs/r1/report.sarif").toAbsolutePath().normalize()
                        + "->" + root.resolve("runs/r1/ai-triage.json").toAbsolutePath().normalize()
                        + ":" + root.resolve("runs/r1/ai-triage.md").toAbsolutePath().normalize()
                        + ":" + root.resolve("runs/r1/findings-ai-triage.json").toAbsolutePath().normalize());
    }

    @Test
    void aiTriageErrorOutcomeProducesFailedNodeWithArtifacts(@TempDir Path root) {
        RecordingStepApis apis = new RecordingStepApis();
        apis.aiTriageResult = new com.oversecured.sast.aitriage.AiTriageAnalyzer.Result(
                com.oversecured.sast.aitriage.AiTriageAnalyzer.Status.ERROR,
                "AI triage failed: RuntimeException: API down", 0);
        PipelineActivitiesImpl activities = PipelineActivitiesImpl.forTesting(root, apis);

        StepResult result = activities.aiTriage(new com.oversecured.sast.orchestrator.activities.AiTriageActivityInput(
                "runs/r1/report.sarif", "runs/r1/sources", "runs/r1/ai-triage.json", "runs/r1/ai-triage.md",
                "runs/r1/findings-ai-triage.json"));

        assertThat(result.state()).isEqualTo(com.oversecured.sast.orchestrator.status.StepState.FAILED);
        assertThat(result.error()).isNotNull();
        assertThat(result.error().kind()).isEqualTo("AI_TRIAGE");
        assertThat(result.message()).contains("AI triage failed");
        assertThat(result.findingsKeys()).isEmpty();
        // The sidecar artifacts are still surfaced on a failed node.
        assertThat(result.artifacts()).containsExactly(
                new ArtifactRef("ai-triage-json", "runs/r1/ai-triage.json"),
                new ArtifactRef("ai-triage-md", "runs/r1/ai-triage.md"),
                new ArtifactRef("findings", "runs/r1/findings-ai-triage.json"));
    }

    @Test
    void permanentPipelineFailureBecomesNonRetryableApplicationFailure(@TempDir Path root) throws Exception {
        RecordingStepApis apis = new RecordingStepApis();
        apis.decompileFailure = new PipelineException(FailureKind.PERMANENT, "apk is empty");
        PipelineActivitiesImpl activities = PipelineActivitiesImpl.forTesting(root, apis);
        Files.writeString(root.resolve("apk.apk"), "fake-apk");

        assertThatThrownBy(() -> activities.decompile(new DecompileActivityInput(
                        root.resolve("apk.apk").toString(),
                        "runs/r1/sources",
                        "runs/r1/sources/AndroidManifest.xml")))
                .isInstanceOfSatisfying(ApplicationFailure.class, failure -> {
                    assertThat(failure.getType()).isEqualTo("PERMANENT");
                    assertThat(failure.isNonRetryable()).isTrue();
                    assertThat(failure.getOriginalMessage()).isEqualTo("apk is empty");
                });
    }

    private static final class RecordingStepApis implements PipelineActivitiesImpl.StepApis {
        private final List<String> calls = new ArrayList<>();
        private PipelineException decompileFailure;

        @Override
        public void decompile(Path apk, Path sourcesDir) {
            if (decompileFailure != null) {
                throw decompileFailure;
            }
            calls.add("decompile:" + apk + "->" + sourcesDir);
            try {
                Files.createDirectories(sourcesDir.resolve("com/example"));
                Files.writeString(sourcesDir.resolve("com/example/MainActivity.java"), "class MainActivity {}");
                Files.writeString(sourcesDir.resolve("com/example/WebViewActivity.java"), "class WebViewActivity {}");
                Files.writeString(sourcesDir.resolve("AndroidManifest.xml"), "<manifest />");
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public void parse(Path sourcesDir, Path astIndexDir) {
            calls.add("parse:" + sourcesDir + "->" + astIndexDir);
            try {
                Files.createDirectories(astIndexDir);
                Files.writeString(astIndexDir.resolve("classes.json"), "{}");
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public void extractManifestFacts(Path manifestXml, Path factsJson) {
            calls.add("mfacts:" + manifestXml + "->" + factsJson);
            try {
                Files.createDirectories(factsJson.getParent());
                Files.writeString(factsJson, "{}");
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public void runTaintBatch(Path astIndexDir, Path factsJson,
                List<PipelineActivitiesImpl.TaintRuleSpec> rules) {
            StringBuilder sb = new StringBuilder("taint-batch:" + astIndexDir);
            for (PipelineActivitiesImpl.TaintRuleSpec spec : rules) {
                sb.append(";").append(spec.name()).append(":").append(spec.ruleYaml()).append("->").append(spec.findingsJson());
            }
            calls.add(sb.toString());
            for (PipelineActivitiesImpl.TaintRuleSpec spec : rules) {
                writeFindings(spec.findingsJson(), spec.name().equals("webview")
                        ? List.of(finding("webview", Severity.ERROR), finding("webview", Severity.WARNING))
                        : List.of(finding("pathtraversal", Severity.WARNING)));
            }
        }

        @Override
        public void runManifestMisconfig(String analysisName, Path factsJson, Path ruleYaml, Path findingsJson) {
            calls.add("misconfig:" + analysisName + ":" + ruleYaml + "->" + findingsJson);
            writeFindings(findingsJson, List.of(finding("exported-activity", Severity.WARNING)));
        }

        @Override
        public void report(List<Path> findingsFiles, Path html, Path sarif) {
            calls.add("report:" + findingsFiles.size() + "->" + html + ":" + sarif);
            try {
                Files.createDirectories(html.getParent());
                Files.writeString(html, "<html></html>");
                Files.writeString(sarif, "{}");
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        private com.oversecured.sast.aitriage.AiTriageAnalyzer.Result aiTriageResult =
                new com.oversecured.sast.aitriage.AiTriageAnalyzer.Result(
                        com.oversecured.sast.aitriage.AiTriageAnalyzer.Status.OK,
                        "AI triage analyzed 1 findings (1 actionable).", 1);

        @Override
        public com.oversecured.sast.aitriage.AiTriageAnalyzer.Result aiTriage(
                Path sarif, Path sourcesDir, Path outJson, Path outMd, Path outFindings) {
            calls.add("aitriage:" + sarif + "->" + outJson + ":" + outMd + ":" + outFindings);
            try {
                Files.createDirectories(outJson.getParent());
                Files.writeString(outJson, "{\"items\":[]}");
                Files.writeString(outMd, "# AI Triage\n");
                Files.writeString(outFindings, "{\"analyzer\":\"ai-triage\",\"findings\":[]}");
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            return aiTriageResult;
        }

        private static Finding finding(String ruleId, Severity severity) {
            return new Finding(ruleId, "test", severity, "message", null, null, List.of(), List.of());
        }

        private static void writeFindings(Path path, List<Finding> findings) {
            try {
                Files.createDirectories(path.getParent());
                Files.writeString(path, Json.writeString(new FindingsDoc("test", findings)));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }
}
