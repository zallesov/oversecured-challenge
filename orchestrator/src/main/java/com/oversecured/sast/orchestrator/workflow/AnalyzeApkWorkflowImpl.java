package com.oversecured.sast.orchestrator.workflow;

import com.oversecured.sast.common.PipelineException;
import com.oversecured.sast.orchestrator.AnalysisPlan;
import com.oversecured.sast.orchestrator.AnalysisResult;
import com.oversecured.sast.orchestrator.AnalyzeApkRequest;
import com.oversecured.sast.orchestrator.TaskQueues;
import com.oversecured.sast.orchestrator.activities.AiTriageActivityInput;
import com.oversecured.sast.orchestrator.activities.DecompileActivityInput;
import com.oversecured.sast.orchestrator.activities.ManifestFactsActivityInput;
import com.oversecured.sast.orchestrator.activities.MisconfigActivityInput;
import com.oversecured.sast.orchestrator.activities.ParseActivityInput;
import com.oversecured.sast.orchestrator.activities.PipelineActivities;
import com.oversecured.sast.orchestrator.activities.ReportActivityInput;
import com.oversecured.sast.orchestrator.activities.TaintBatchActivityInput;
import com.oversecured.sast.orchestrator.status.RunStatus;
import com.oversecured.sast.orchestrator.status.RunStatusBuilder;
import com.oversecured.sast.orchestrator.status.StepError;
import com.oversecured.sast.orchestrator.status.StepResult;
import com.oversecured.sast.orchestrator.status.StepState;
import io.temporal.activity.ActivityOptions;
import io.temporal.common.RetryOptions;
import io.temporal.failure.ApplicationFailure;
import io.temporal.workflow.Async;
import io.temporal.workflow.Promise;
import io.temporal.workflow.Workflow;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public final class AnalyzeApkWorkflowImpl implements AnalyzeApkWorkflow {
    private static final String DECOMPILE = "decompile";
    private static final String PARSE = "parse";
    private static final String MANIFEST_FACTS = "manifest-facts";
    private static final String TAINT = "taint";
    private static final String MANIFEST_MISCONFIG = "manifest-misconfig";
    private static final String REPORT = "report";
    private static final String AI_TRIAGE = "ai-triage";

    private final PipelineActivities activities = Workflow.newActivityStub(
            PipelineActivities.class,
            ActivityOptions.newBuilder()
                    .setTaskQueue(TaskQueues.DEFAULT)
                    .setStartToCloseTimeout(Duration.ofMinutes(30))
                    .setScheduleToCloseTimeout(Duration.ofHours(2))
                    .setRetryOptions(RetryOptions.newBuilder()
                            .setInitialInterval(Duration.ofSeconds(1))
                            .setBackoffCoefficient(2.0)
                            .setMaximumInterval(Duration.ofSeconds(30))
                            .setMaximumAttempts(3)
                            .setDoNotRetry("PERMANENT")
                            .build())
                    .build());

    private RunStatusBuilder status;

    @Override
    public AnalysisResult analyze(AnalyzeApkRequest request) {
        AnalysisPlan plan = request.plan();
        status = new RunStatusBuilder(
                plan.runId(),
                nodeDefinitions(),
                () -> Instant.ofEpochMilli(Workflow.currentTimeMillis()));

        runStep(DECOMPILE, "Decompiling APK.", () -> activities.decompile(new DecompileActivityInput(
                        request.apkPath(),
                        plan.keys().sourcesDirKey(),
                        plan.keys().manifestKey())));

        Promise<StepResult> astIndex = runAsyncStep(PARSE, "Parsing sources.", () ->
                activities.parseSources(new ParseActivityInput(
                        plan.keys().sourcesDirKey(),
                        plan.keys().astIndexDirKey())));

        Promise<StepResult> facts = runAsyncStep(MANIFEST_FACTS, "Extracting manifest facts.", () ->
                activities.extractManifestFacts(new ManifestFactsActivityInput(
                        plan.keys().manifestKey(),
                        plan.keys().factsKey())));

        Promise.allOf(astIndex, facts).get();

        // All taint rules share one AST-index load (one re-parse, one android.jar solver) instead of
        // one re-parsing activity per rule; runs in parallel with the manifest-misconfig branch.
        List<TaintBatchActivityInput.Rule> taintRules = new ArrayList<>();
        for (AnalysisPlan.TaintAnalysis taint : plan.taintAnalyses()) {
            taintRules.add(new TaintBatchActivityInput.Rule(
                    taint.name(),
                    taint.rulePath(),
                    taint.findingsKey()));
        }
        Promise<StepResult> taintFindings = runAsyncStep(TAINT, "Running taint analysis.", () ->
                activities.runTaintBatch(new TaintBatchActivityInput(
                        plan.keys().astIndexDirKey(),
                        plan.keys().factsKey(),
                        taintRules)));

        Promise<StepResult> misconfigFindings = runAsyncStep(
                MANIFEST_MISCONFIG,
                "Running manifest misconfiguration analysis.",
                () -> activities.runManifestMisconfig(new MisconfigActivityInput(
                                plan.manifestMisconfig().name(),
                                plan.keys().factsKey(),
                                plan.manifestMisconfig().rulePath(),
                                plan.manifestMisconfig().findingsKey())));

        Promise.allOf(taintFindings, misconfigFindings).get();

        runStep(REPORT, "Building report.", () -> activities.report(new ReportActivityInput(
                plan.findingsKeysForReporter(),
                plan.report().htmlKey(),
                plan.report().sarifKey())));

        // Soft step: the activity is fail-soft and returns a settled StepResult (COMPLETED or
        // FAILED). A FAILED ai-triage node is recorded as-is but never fails the overall scan.
        runSoftStep(AI_TRIAGE, "Running AI triage.", () -> activities.aiTriage(new AiTriageActivityInput(
                plan.report().sarifKey(),
                plan.keys().sourcesDirKey(),
                plan.report().aiTriageJsonKey(),
                plan.report().aiTriageMdKey())));

        return new AnalysisResult(
                plan.report().htmlKey(),
                plan.report().sarifKey(),
                plan.report().aiTriageJsonKey(),
                plan.report().aiTriageMdKey());
    }

    @Override
    public RunStatus getStatus() {
        if (status == null) {
            return new RunStatus(
                    "unknown",
                    StepState.QUEUED,
                    "Queued.",
                    null,
                    null,
                    null,
                    List.of());
        }
        return status.snapshot();
    }

    private StepResult runStep(String nodeId, String message, ActivityCall call) {
        status.markRunning(nodeId, message);
        try {
            StepResult result = call.call();
            status.markCompleted(result);
            return result;
        } catch (RuntimeException e) {
            markFailed(nodeId, e);
            throw e;
        }
    }

    /**
     * Run a step that reports its own outcome and must not fail the scan. The activity is expected
     * never to throw; its returned StepResult (COMPLETED or FAILED) is recorded verbatim.
     */
    private StepResult runSoftStep(String nodeId, String message, ActivityCall call) {
        status.markRunning(nodeId, message);
        try {
            StepResult result = call.call();
            status.markSettled(result);
            return result;
        } catch (RuntimeException e) {
            // Defensive: a soft step should not throw, but if it does, record it without failing
            // the run so a single optional step cannot sink an otherwise complete scan.
            StepResult failure = StepResult.failed(
                    nodeId,
                    e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage(),
                    new StepError("UNKNOWN", e.getMessage()));
            status.markSettled(failure);
            return failure;
        }
    }

    private Promise<StepResult> runAsyncStep(String nodeId, String message, ActivityCall call) {
        status.markRunning(nodeId, message);
        return Async.function(() -> runStepBody(nodeId, call));
    }

    private StepResult runStepBody(String nodeId, ActivityCall call) {
        try {
            StepResult result = call.call();
            status.markCompleted(result);
            return result;
        } catch (RuntimeException e) {
            markFailed(nodeId, e);
            throw e;
        }
    }

    private void markFailed(String nodeId, RuntimeException e) {
        PipelineException pipelineException = pipelineException(e);
        ApplicationFailure applicationFailure = applicationFailure(e);
        String kind = "UNKNOWN";
        String message = e.getMessage();
        if (pipelineException != null) {
            kind = pipelineException.kind().name();
            message = pipelineException.getMessage();
        } else if (applicationFailure != null && isPipelineFailureType(applicationFailure.getType())) {
            kind = applicationFailure.getType();
            message = applicationFailure.getOriginalMessage();
        }
        if (message == null || message.isBlank()) {
            message = e.getClass().getSimpleName();
        }
        status.markFailed(StepResult.failed(
                nodeId,
                message,
                new StepError(kind, message)));
    }

    private PipelineException pipelineException(Throwable throwable) {
        Throwable current = throwable;
        while (current != null) {
            if (current instanceof PipelineException pipelineException) {
                return pipelineException;
            }
            current = current.getCause();
        }
        return null;
    }

    private ApplicationFailure applicationFailure(Throwable throwable) {
        Throwable current = throwable;
        while (current != null) {
            if (current instanceof ApplicationFailure applicationFailure) {
                return applicationFailure;
            }
            current = current.getCause();
        }
        return null;
    }

    private static boolean isPipelineFailureType(String type) {
        return "PERMANENT".equals(type) || "TRANSIENT".equals(type);
    }

    private List<RunStatusBuilder.NodeDefinition> nodeDefinitions() {
        return List.of(
                new RunStatusBuilder.NodeDefinition(DECOMPILE, "Decompile", "preparation"),
                new RunStatusBuilder.NodeDefinition(PARSE, "Parse Sources", "preparation"),
                new RunStatusBuilder.NodeDefinition(MANIFEST_FACTS, "Manifest Facts", "preparation"),
                new RunStatusBuilder.NodeDefinition(TAINT, "Taint Analysis", "analyzer"),
                new RunStatusBuilder.NodeDefinition(MANIFEST_MISCONFIG, "Manifest Misconfiguration", "analyzer"),
                new RunStatusBuilder.NodeDefinition(REPORT, "Report", "report"),
                new RunStatusBuilder.NodeDefinition(AI_TRIAGE, "AI Triage", "report"));
    }

    @FunctionalInterface
    private interface ActivityCall {
        StepResult call();
    }
}
