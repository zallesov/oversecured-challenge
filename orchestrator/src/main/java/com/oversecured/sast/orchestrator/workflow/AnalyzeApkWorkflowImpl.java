package com.oversecured.sast.orchestrator.workflow;

import com.oversecured.sast.orchestrator.AnalysisPlan;
import com.oversecured.sast.orchestrator.AnalysisResult;
import com.oversecured.sast.orchestrator.AnalyzeApkRequest;
import com.oversecured.sast.orchestrator.TaskQueues;
import com.oversecured.sast.orchestrator.activities.DecompileActivityInput;
import com.oversecured.sast.orchestrator.activities.ManifestFactsActivityInput;
import com.oversecured.sast.orchestrator.activities.MisconfigActivityInput;
import com.oversecured.sast.orchestrator.activities.ParseActivityInput;
import com.oversecured.sast.orchestrator.activities.PipelineActivities;
import com.oversecured.sast.orchestrator.activities.ReportActivityInput;
import com.oversecured.sast.orchestrator.activities.ReportArtifacts;
import com.oversecured.sast.orchestrator.activities.TaintBatchActivityInput;
import io.temporal.activity.ActivityOptions;
import io.temporal.common.RetryOptions;
import io.temporal.workflow.Async;
import io.temporal.workflow.Promise;
import io.temporal.workflow.Workflow;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

public final class AnalyzeApkWorkflowImpl implements AnalyzeApkWorkflow {

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
                            .build())
                    .build());

    @Override
    public AnalysisResult analyze(AnalyzeApkRequest request) {
        AnalysisPlan plan = request.plan();

        String sourcesDirKey = activities.decompile(new DecompileActivityInput(
                request.apkPath(),
                plan.keys().sourcesDirKey(),
                plan.keys().manifestKey()));

        Promise<String> astIndex = Async.function(activities::parseSources, new ParseActivityInput(
                sourcesDirKey,
                plan.keys().astIndexDirKey()));

        Promise<String> facts = Async.function(activities::extractManifestFacts, new ManifestFactsActivityInput(
                plan.keys().manifestKey(),
                plan.keys().factsKey()));

        Promise.allOf(astIndex, facts).get();

        String astIndexDirKey = astIndex.get();
        String factsKey = facts.get();

        // All taint rules share one AST-index load (one re-parse, one android.jar solver) instead of
        // one re-parsing activity per rule; runs in parallel with the manifest-misconfig branch.
        List<TaintBatchActivityInput.Rule> taintRules = new ArrayList<>();
        for (AnalysisPlan.TaintAnalysis taint : plan.taintAnalyses()) {
            taintRules.add(new TaintBatchActivityInput.Rule(
                    taint.name(),
                    taint.rulePath(),
                    taint.findingsKey()));
        }
        Promise<List<String>> taintFindings = Async.function(activities::runTaintBatch,
                new TaintBatchActivityInput(astIndexDirKey, factsKey, taintRules));
        Promise<String> misconfigFindings = Async.function(activities::runManifestMisconfig,
                new MisconfigActivityInput(
                        plan.manifestMisconfig().name(),
                        factsKey,
                        plan.manifestMisconfig().rulePath(),
                        plan.manifestMisconfig().findingsKey()));

        Promise.allOf(taintFindings, misconfigFindings).get();

        ReportArtifacts report = activities.report(new ReportActivityInput(
                plan.findingsKeysForReporter(),
                plan.report().htmlKey(),
                plan.report().sarifKey()));

        return new AnalysisResult(report.htmlKey(), report.sarifKey());
    }
}
