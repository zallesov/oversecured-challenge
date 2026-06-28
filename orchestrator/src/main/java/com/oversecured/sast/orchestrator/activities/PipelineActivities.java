package com.oversecured.sast.orchestrator.activities;

import com.oversecured.sast.orchestrator.status.StepResult;
import io.temporal.activity.ActivityInterface;
import io.temporal.activity.ActivityMethod;

@ActivityInterface
public interface PipelineActivities {

    @ActivityMethod
    StepResult decompile(DecompileActivityInput input);

    @ActivityMethod
    StepResult parseSources(ParseActivityInput input);

    @ActivityMethod
    StepResult extractManifestFacts(ManifestFactsActivityInput input);

    /** Run all taint rules from a single AST-index load. */
    @ActivityMethod
    StepResult runTaintBatch(TaintBatchActivityInput input);

    @ActivityMethod
    StepResult runManifestMisconfig(MisconfigActivityInput input);

    @ActivityMethod
    StepResult report(ReportActivityInput input);
}
