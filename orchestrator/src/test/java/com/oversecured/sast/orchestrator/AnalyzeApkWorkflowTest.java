package com.oversecured.sast.orchestrator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.oversecured.sast.orchestrator.activities.DecompileActivityInput;
import com.oversecured.sast.orchestrator.activities.ManifestFactsActivityInput;
import com.oversecured.sast.orchestrator.activities.MisconfigActivityInput;
import com.oversecured.sast.orchestrator.activities.ParseActivityInput;
import com.oversecured.sast.orchestrator.activities.PipelineActivities;
import com.oversecured.sast.orchestrator.activities.ReportActivityInput;
import com.oversecured.sast.orchestrator.activities.ReportArtifacts;
import com.oversecured.sast.orchestrator.activities.TaintActivityInput;
import com.oversecured.sast.orchestrator.workflow.AnalyzeApkWorkflow;
import com.oversecured.sast.orchestrator.workflow.AnalyzeApkWorkflowImpl;
import io.temporal.client.WorkflowClient;
import io.temporal.client.WorkflowOptions;
import io.temporal.testing.TestWorkflowEnvironment;
import io.temporal.worker.Worker;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class AnalyzeApkWorkflowTest {

    private TestWorkflowEnvironment testEnv;

    @AfterEach
    void closeTemporalEnvironment() {
        if (testEnv != null) {
            testEnv.close();
        }
    }

    @Test
    void workflowWiresDAGOrderAndArtifactKeys() {
        RecordingActivities activities = new RecordingActivities(false);
        AnalyzeApkWorkflow workflow = newWorkflow(activities);

        AnalysisResult result = workflow.analyze(
                new AnalyzeApkRequest("/tmp/ovaa.apk", AnalysisPlan.defaultPlan("run-1")));

        assertThat(result).isEqualTo(new AnalysisResult(
                "runs/run-1/report.html",
                "runs/run-1/report.sarif"));

        assertThat(activities.calls.get(0)).isEqualTo("decompile:runs/run-1/sources");
        assertThat(activities.calls.subList(1, 3)).containsExactlyInAnyOrder(
                "parse:runs/run-1/ast-index",
                "manifest-facts:runs/run-1/facts.json");
        assertThat(activities.calls.subList(3, 6)).containsExactlyInAnyOrder(
                "taint:webview:runs/run-1/findings-webview.json",
                "taint:pathtraversal:runs/run-1/findings-pathtraversal.json",
                "misconfig:manifest-misconfig:runs/run-1/findings-misconfig.json");
        assertThat(activities.calls).endsWith("report:runs/run-1/report.html:runs/run-1/report.sarif");

        assertThat(activities.reportInput.findingsKeys()).containsExactly(
                "runs/run-1/findings-webview.json",
                "runs/run-1/findings-pathtraversal.json",
                "runs/run-1/findings-misconfig.json");
    }

    @Test
    void workflowStartsPrerequisitesAndAnalyzersAsFanOutBranches() {
        RecordingActivities activities = new RecordingActivities(true);
        AnalyzeApkWorkflow workflow = newWorkflow(activities);

        AnalysisResult result = workflow.analyze(
                new AnalyzeApkRequest("/tmp/ovaa.apk", AnalysisPlan.defaultPlan("fanout-1")));

        assertThat(result.htmlReportKey()).isEqualTo("runs/fanout-1/report.html");
        assertThat(activities.parseAndFactsWereConcurrentlyStarted).isTrue();
        assertThat(activities.analyzersWereConcurrentlyStarted).isTrue();
    }

    @Test
    void transientAnalyzerFailureRetriesWithSameOutputKey() {
        RetryRecordingActivities activities = new RetryRecordingActivities(2);
        AnalyzeApkWorkflow workflow = newWorkflow(activities);

        AnalysisResult result = workflow.analyze(
                new AnalyzeApkRequest("/tmp/ovaa.apk", AnalysisPlan.defaultPlan("retry-1")));

        assertThat(result.sarifReportKey()).isEqualTo("runs/retry-1/report.sarif");
        assertThat(activities.webviewAttempts).isEqualTo(2);
        assertThat(activities.webviewKeys).containsExactly(
                "runs/retry-1/findings-webview.json",
                "runs/retry-1/findings-webview.json");
        assertThat(activities.reportCalled).isTrue();
    }

    @Test
    void permanentDecompilerFailureStopsDownstreamActivities() {
        RetryRecordingActivities activities = new RetryRecordingActivities(Integer.MAX_VALUE);
        activities.failDecompile = true;
        AnalyzeApkWorkflow workflow = newWorkflow(activities);

        assertThatThrownBy(() -> workflow.analyze(
                        new AnalyzeApkRequest("/tmp/missing.apk", AnalysisPlan.defaultPlan("fail-1"))))
                .hasStackTraceContaining("decompile failed");

        assertThat(activities.parseCalled).isFalse();
        assertThat(activities.reportCalled).isFalse();
    }

    private AnalyzeApkWorkflow newWorkflow(PipelineActivities activities) {
        testEnv = TestWorkflowEnvironment.newInstance();
        Worker worker = testEnv.newWorker(TaskQueues.DEFAULT);
        worker.registerWorkflowImplementationTypes(AnalyzeApkWorkflowImpl.class);
        worker.registerActivitiesImplementations(activities);
        testEnv.start();

        WorkflowClient client = testEnv.getWorkflowClient();
        return client.newWorkflowStub(
                AnalyzeApkWorkflow.class,
                WorkflowOptions.newBuilder()
                        .setWorkflowId("test-" + System.nanoTime())
                        .setTaskQueue(TaskQueues.DEFAULT)
                        .setWorkflowRunTimeout(Duration.ofMinutes(1))
                        .build());
    }

    private static final class RecordingActivities implements PipelineActivities {
        private final boolean requireConcurrentFanOut;
        private final List<String> calls = new ArrayList<>();
        private final CountDownLatch prereqStarted = new CountDownLatch(2);
        private final CountDownLatch analyzerStarted = new CountDownLatch(3);
        private boolean parseAndFactsWereConcurrentlyStarted;
        private boolean analyzersWereConcurrentlyStarted;
        private ReportActivityInput reportInput;

        private RecordingActivities(boolean requireConcurrentFanOut) {
            this.requireConcurrentFanOut = requireConcurrentFanOut;
        }

        @Override
        public synchronized String decompile(DecompileActivityInput input) {
            calls.add("decompile:" + input.sourcesDirKey());
            return input.sourcesDirKey();
        }

        @Override
        public String parseSources(ParseActivityInput input) {
            awaitFanOutIfRequired(prereqStarted);
            synchronized (this) {
                parseAndFactsWereConcurrentlyStarted = true;
                calls.add("parse:" + input.astIndexDirKey());
            }
            return input.astIndexDirKey();
        }

        @Override
        public String extractManifestFacts(ManifestFactsActivityInput input) {
            awaitFanOutIfRequired(prereqStarted);
            synchronized (this) {
                parseAndFactsWereConcurrentlyStarted = true;
                calls.add("manifest-facts:" + input.factsKey());
            }
            return input.factsKey();
        }

        @Override
        public String runTaint(TaintActivityInput input) {
            awaitFanOutIfRequired(analyzerStarted);
            synchronized (this) {
                analyzersWereConcurrentlyStarted = true;
                calls.add("taint:" + input.analysisName() + ":" + input.findingsKey());
            }
            return input.findingsKey();
        }

        @Override
        public String runManifestMisconfig(MisconfigActivityInput input) {
            awaitFanOutIfRequired(analyzerStarted);
            synchronized (this) {
                analyzersWereConcurrentlyStarted = true;
                calls.add("misconfig:" + input.analysisName() + ":" + input.findingsKey());
            }
            return input.findingsKey();
        }

        @Override
        public synchronized ReportArtifacts report(ReportActivityInput input) {
            this.reportInput = input;
            calls.add("report:" + input.htmlKey() + ":" + input.sarifKey());
            return new ReportArtifacts(input.htmlKey(), input.sarifKey());
        }

        private void awaitFanOutIfRequired(CountDownLatch latch) {
            if (!requireConcurrentFanOut) {
                return;
            }
            latch.countDown();
            try {
                if (!latch.await(5, TimeUnit.SECONDS)) {
                    throw new AssertionError("fan-out branch did not start concurrently");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new AssertionError("interrupted while waiting for fan-out", e);
            }
        }
    }

    private static final class RetryRecordingActivities implements PipelineActivities {
        private final int webviewSucceedsOnAttempt;
        private int webviewAttempts;
        private final List<String> webviewKeys = new ArrayList<>();
        private boolean failDecompile;
        private boolean parseCalled;
        private boolean reportCalled;

        private RetryRecordingActivities(int webviewSucceedsOnAttempt) {
            this.webviewSucceedsOnAttempt = webviewSucceedsOnAttempt;
        }

        @Override
        public String decompile(DecompileActivityInput input) {
            if (failDecompile) {
                throw new IllegalStateException("decompile failed");
            }
            return input.sourcesDirKey();
        }

        @Override
        public String parseSources(ParseActivityInput input) {
            parseCalled = true;
            return input.astIndexDirKey();
        }

        @Override
        public String extractManifestFacts(ManifestFactsActivityInput input) {
            return input.factsKey();
        }

        @Override
        public String runTaint(TaintActivityInput input) {
            if ("webview".equals(input.analysisName())) {
                webviewAttempts++;
                webviewKeys.add(input.findingsKey());
                if (webviewAttempts < webviewSucceedsOnAttempt) {
                    throw new IllegalStateException("temporary taint failure");
                }
            }
            return input.findingsKey();
        }

        @Override
        public String runManifestMisconfig(MisconfigActivityInput input) {
            return input.findingsKey();
        }

        @Override
        public ReportArtifacts report(ReportActivityInput input) {
            reportCalled = true;
            return new ReportArtifacts(input.htmlKey(), input.sarifKey());
        }
    }
}
