package com.oversecured.sast.orchestrator;

import static org.assertj.core.api.Assertions.assertThat;

import com.oversecured.sast.orchestrator.activities.DecompileActivityInput;
import com.oversecured.sast.orchestrator.activities.ManifestFactsActivityInput;
import com.oversecured.sast.orchestrator.activities.MisconfigActivityInput;
import com.oversecured.sast.orchestrator.activities.ParseActivityInput;
import com.oversecured.sast.orchestrator.activities.PipelineActivitiesImpl;
import com.oversecured.sast.orchestrator.activities.ReportActivityInput;
import com.oversecured.sast.orchestrator.activities.ReportArtifacts;
import com.oversecured.sast.orchestrator.activities.TaintActivityInput;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PipelineActivitiesImplTest {

    @Test
    void activitiesResolveKeysAndReturnRequestedOutputs(@TempDir Path root) throws Exception {
        RecordingStepApis apis = new RecordingStepApis();
        PipelineActivitiesImpl activities = PipelineActivitiesImpl.forTesting(root, apis);
        Files.writeString(root.resolve("apk.apk"), "fake-apk");

        String sourcesKey = activities.decompile(new DecompileActivityInput(
                root.resolve("apk.apk").toString(),
                "runs/r1/sources",
                "runs/r1/sources/AndroidManifest.xml"));
        String astKey = activities.parseSources(new ParseActivityInput(
                "runs/r1/sources",
                "runs/r1/ast-index"));
        String factsKey = activities.extractManifestFacts(new ManifestFactsActivityInput(
                "runs/r1/sources/AndroidManifest.xml",
                "runs/r1/facts.json"));
        String webviewKey = activities.runTaint(new TaintActivityInput(
                "webview",
                "runs/r1/ast-index",
                "runs/r1/facts.json",
                "rules/webview.yaml",
                "runs/r1/findings-webview.json"));
        String misconfigKey = activities.runManifestMisconfig(new MisconfigActivityInput(
                "manifest-misconfig",
                "runs/r1/facts.json",
                "rules/misconfig.yaml",
                "runs/r1/findings-misconfig.json"));
        ReportArtifacts reports = activities.report(new ReportActivityInput(
                List.of(webviewKey, misconfigKey),
                "runs/r1/report.html",
                "runs/r1/report.sarif"));

        assertThat(sourcesKey).isEqualTo("runs/r1/sources");
        assertThat(astKey).isEqualTo("runs/r1/ast-index");
        assertThat(factsKey).isEqualTo("runs/r1/facts.json");
        assertThat(webviewKey).isEqualTo("runs/r1/findings-webview.json");
        assertThat(misconfigKey).isEqualTo("runs/r1/findings-misconfig.json");
        assertThat(reports).isEqualTo(new ReportArtifacts("runs/r1/report.html", "runs/r1/report.sarif"));

        assertThat(apis.calls).containsExactly(
                "decompile:" + root.resolve("apk.apk").toAbsolutePath().normalize() + "->" + root.resolve("runs/r1/sources").toAbsolutePath().normalize(),
                "parse:" + root.resolve("runs/r1/sources").toAbsolutePath().normalize() + "->" + root.resolve("runs/r1/ast-index").toAbsolutePath().normalize(),
                "mfacts:" + root.resolve("runs/r1/sources/AndroidManifest.xml").toAbsolutePath().normalize() + "->" + root.resolve("runs/r1/facts.json").toAbsolutePath().normalize(),
                "taint:webview:" + root.resolve("rules/webview.yaml").toAbsolutePath().normalize() + "->" + root.resolve("runs/r1/findings-webview.json").toAbsolutePath().normalize(),
                "misconfig:manifest-misconfig:" + root.resolve("rules/misconfig.yaml").toAbsolutePath().normalize() + "->" + root.resolve("runs/r1/findings-misconfig.json").toAbsolutePath().normalize(),
                "report:2->" + root.resolve("runs/r1/report.html").toAbsolutePath().normalize() + ":" + root.resolve("runs/r1/report.sarif").toAbsolutePath().normalize());
    }

    private static final class RecordingStepApis implements PipelineActivitiesImpl.StepApis {
        private final List<String> calls = new ArrayList<>();

        @Override
        public void decompile(Path apk, Path sourcesDir) {
            calls.add("decompile:" + apk + "->" + sourcesDir);
        }

        @Override
        public void parse(Path sourcesDir, Path astIndexDir) {
            calls.add("parse:" + sourcesDir + "->" + astIndexDir);
        }

        @Override
        public void extractManifestFacts(Path manifestXml, Path factsJson) {
            calls.add("mfacts:" + manifestXml + "->" + factsJson);
        }

        @Override
        public void runTaint(String analysisName, Path astIndexDir, Path factsJson, Path ruleYaml, Path findingsJson) {
            calls.add("taint:" + analysisName + ":" + ruleYaml + "->" + findingsJson);
        }

        @Override
        public void runManifestMisconfig(String analysisName, Path factsJson, Path ruleYaml, Path findingsJson) {
            calls.add("misconfig:" + analysisName + ":" + ruleYaml + "->" + findingsJson);
        }

        @Override
        public void report(List<Path> findingsFiles, Path html, Path sarif) {
            calls.add("report:" + findingsFiles.size() + "->" + html + ":" + sarif);
        }
    }
}
