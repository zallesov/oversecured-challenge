package com.oversecured.sast.orchestrator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.oversecured.sast.orchestrator.activities.DecompileActivityInput;
import com.oversecured.sast.orchestrator.activities.ManifestFactsActivityInput;
import com.oversecured.sast.orchestrator.activities.MisconfigActivityInput;
import com.oversecured.sast.orchestrator.activities.ParseActivityInput;
import com.oversecured.sast.orchestrator.activities.PipelineActivities;
import com.oversecured.sast.orchestrator.activities.ReportActivityInput;
import com.oversecured.sast.orchestrator.activities.TaintBatchActivityInput;
import com.oversecured.sast.orchestrator.status.NodeStatus;
import com.oversecured.sast.orchestrator.status.RunStatus;
import com.oversecured.sast.orchestrator.status.StepResult;
import com.oversecured.sast.orchestrator.status.StepState;
import com.oversecured.sast.orchestrator.workflow.AnalyzeApkWorkflow;
import com.oversecured.sast.orchestrator.workflow.AnalyzeApkWorkflowImpl;
import io.temporal.client.WorkflowClient;
import io.temporal.client.WorkflowOptions;
import io.temporal.failure.ApplicationFailure;
import io.temporal.testing.TestWorkflowEnvironment;
import io.temporal.worker.Worker;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
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
                new AnalyzeApkRequest("/tmp/ovaa.apk",
                        AnalysisPlan.forRules("run-1", List.of("webview", "pathtraversal"))));

        assertThat(result).isEqualTo(new AnalysisResult(
                "runs/run-1/report.html",
                "runs/run-1/report.sarif",
                "runs/run-1/ai-triage.json",
                "runs/run-1/ai-triage.md"));

        assertThat(activities.calls.get(0)).isEqualTo("decompile:runs/run-1/sources");
        assertThat(activities.calls.subList(1, 3)).containsExactlyInAnyOrder(
                "parse:runs/run-1/ast-index",
                "manifest-facts:runs/run-1/facts.json");
        assertThat(activities.calls.subList(3, 5)).containsExactlyInAnyOrder(
                "taint-batch:webview,pathtraversal",
                "misconfig:manifest-misconfig:runs/run-1/findings-misconfig.json");
        assertThat(activities.calls).containsSubsequence(
                "report:runs/run-1/report.html:runs/run-1/report.sarif",
                "aitriage:runs/run-1/ai-triage.json:runs/run-1/ai-triage.md");
        assertThat(activities.calls).endsWith("aitriage:runs/run-1/ai-triage.json:runs/run-1/ai-triage.md");

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
                new AnalyzeApkRequest("/tmp/ovaa.apk",
                        AnalysisPlan.forRules("fanout-1", List.of("webview", "pathtraversal"))));

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

    @Test
    void workflowStatusReportsTypedPermanentFailure() {
        RetryRecordingActivities activities = new RetryRecordingActivities(Integer.MAX_VALUE);
        activities.failDecompileWithPermanentApplicationFailure = true;
        AnalyzeApkWorkflow workflow = newWorkflow(activities);

        assertThatThrownBy(() -> workflow.analyze(
                        new AnalyzeApkRequest("/tmp/empty.apk", AnalysisPlan.defaultPlan("fail-status-1"))))
                .hasStackTraceContaining("apk is empty");

        NodeStatus decompile = workflow.getStatus().nodes().stream()
                .filter(node -> node.id().equals("decompile"))
                .findFirst()
                .orElseThrow();
        assertThat(decompile.state()).isEqualTo(StepState.FAILED);
        assertThat(decompile.error().kind()).isEqualTo("PERMANENT");
        assertThat(decompile.error().message()).isEqualTo("apk is empty");
        assertThat(activities.parseCalled).isFalse();
    }

    @Test
    void workflowStatusQueryShowsCompletedNodesWithDurationsAndFindingCounts() {
        RecordingActivities activities = new RecordingActivities(false);
        AnalyzeApkWorkflow workflow = newWorkflow(activities);

        workflow.analyze(new AnalyzeApkRequest(
                "/tmp/ovaa.apk",
                AnalysisPlan.forRules("status-1", List.of("webview"))));

        RunStatus status = workflow.getStatus();

        assertThat(status.runId()).isEqualTo("status-1");
        assertThat(status.state()).isEqualTo(StepState.COMPLETED);
        assertThat(status.nodes()).extracting(NodeStatus::id).containsExactly(
                "decompile",
                "parse",
                "manifest-facts",
                "taint",
                "manifest-misconfig",
                "report",
                "ai-triage");

        NodeStatus taint = status.nodes().stream()
                .filter(node -> node.id().equals("taint"))
                .findFirst()
                .orElseThrow();
        assertThat(taint.state()).isEqualTo(StepState.COMPLETED);
        assertThat(taint.startedAt()).isNotNull();
        assertThat(taint.finishedAt()).isNotNull();
        assertThat(taint.durationMs()).isNotNull();
        assertThat(taint.findingCount()).isZero();
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
        private final CountDownLatch analyzerStarted = new CountDownLatch(2);
        private boolean parseAndFactsWereConcurrentlyStarted;
        private boolean analyzersWereConcurrentlyStarted;
        private ReportActivityInput reportInput;

        private RecordingActivities(boolean requireConcurrentFanOut) {
            this.requireConcurrentFanOut = requireConcurrentFanOut;
        }

        @Override
        public synchronized StepResult decompile(DecompileActivityInput input) {
            calls.add("decompile:" + input.sourcesDirKey());
            return completed("decompile");
        }

        @Override
        public StepResult parseSources(ParseActivityInput input) {
            awaitFanOutIfRequired(prereqStarted);
            synchronized (this) {
                parseAndFactsWereConcurrentlyStarted = true;
                calls.add("parse:" + input.astIndexDirKey());
            }
            return completed("parse");
        }

        @Override
        public StepResult extractManifestFacts(ManifestFactsActivityInput input) {
            awaitFanOutIfRequired(prereqStarted);
            synchronized (this) {
                parseAndFactsWereConcurrentlyStarted = true;
                calls.add("manifest-facts:" + input.factsKey());
            }
            return completed("manifest-facts");
        }

        @Override
        public StepResult runTaintBatch(TaintBatchActivityInput input) {
            awaitFanOutIfRequired(analyzerStarted);
            List<String> findingsKeys = new ArrayList<>();
            List<String> names = new ArrayList<>();
            for (TaintBatchActivityInput.Rule rule : input.rules()) {
                names.add(rule.name());
                findingsKeys.add(rule.findingsKey());
            }
            synchronized (this) {
                analyzersWereConcurrentlyStarted = true;
                calls.add("taint-batch:" + String.join(",", names));
            }
            return completed("taint", findingsKeys, 0);
        }

        @Override
        public StepResult runManifestMisconfig(MisconfigActivityInput input) {
            awaitFanOutIfRequired(analyzerStarted);
            synchronized (this) {
                analyzersWereConcurrentlyStarted = true;
                calls.add("misconfig:" + input.analysisName() + ":" + input.findingsKey());
            }
            return completed("manifest-misconfig", List.of(input.findingsKey()), 0);
        }

        @Override
        public synchronized StepResult report(ReportActivityInput input) {
            this.reportInput = input;
            calls.add("report:" + input.htmlKey() + ":" + input.sarifKey());
            return completed("report");
        }

        @Override
        public synchronized StepResult aiTriage(
                com.oversecured.sast.orchestrator.activities.AiTriageActivityInput input) {
            calls.add("aitriage:" + input.outJsonKey() + ":" + input.outMdKey());
            return completed("ai-triage");
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
        private boolean failDecompileWithPermanentApplicationFailure;
        private boolean parseCalled;
        private boolean reportCalled;

        private RetryRecordingActivities(int webviewSucceedsOnAttempt) {
            this.webviewSucceedsOnAttempt = webviewSucceedsOnAttempt;
        }

        @Override
        public StepResult decompile(DecompileActivityInput input) {
            if (failDecompileWithPermanentApplicationFailure) {
                throw ApplicationFailure.newNonRetryableFailure("apk is empty", "PERMANENT");
            }
            if (failDecompile) {
                throw new IllegalStateException("decompile failed");
            }
            return completed("decompile");
        }

        @Override
        public StepResult parseSources(ParseActivityInput input) {
            parseCalled = true;
            return completed("parse");
        }

        @Override
        public StepResult extractManifestFacts(ManifestFactsActivityInput input) {
            return completed("manifest-facts");
        }

        @Override
        public StepResult runTaintBatch(TaintBatchActivityInput input) {
            webviewAttempts++;
            List<String> findingsKeys = new ArrayList<>();
            for (TaintBatchActivityInput.Rule rule : input.rules()) {
                findingsKeys.add(rule.findingsKey());
                if ("webview".equals(rule.name())) {
                    webviewKeys.add(rule.findingsKey());
                }
            }
            if (webviewAttempts < webviewSucceedsOnAttempt) {
                throw new IllegalStateException("temporary taint failure");
            }
            return completed("taint", findingsKeys, 0);
        }

        @Override
        public StepResult runManifestMisconfig(MisconfigActivityInput input) {
            return completed("manifest-misconfig", List.of(input.findingsKey()), 0);
        }

        @Override
        public StepResult report(ReportActivityInput input) {
            reportCalled = true;
            return completed("report");
        }

        @Override
        public StepResult aiTriage(com.oversecured.sast.orchestrator.activities.AiTriageActivityInput input) {
            return completed("ai-triage");
        }
    }

    private static StepResult completed(String nodeId) {
        return completed(nodeId, List.of(), 0);
    }

    private static StepResult completed(String nodeId, List<String> findingsKeys, int findingCount) {
        return StepResult.completed(
                nodeId,
                "Completed " + nodeId + ".",
                Map.of(),
                List.of(),
                findingsKeys,
                findingCount,
                Map.of());
    }
}
