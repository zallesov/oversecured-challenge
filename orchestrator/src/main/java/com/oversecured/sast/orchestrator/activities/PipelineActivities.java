package com.oversecured.sast.orchestrator.activities;

import io.temporal.activity.ActivityInterface;
import io.temporal.activity.ActivityMethod;
import java.util.List;

@ActivityInterface
public interface PipelineActivities {

    @ActivityMethod
    String decompile(DecompileActivityInput input);

    @ActivityMethod
    String parseSources(ParseActivityInput input);

    @ActivityMethod
    String extractManifestFacts(ManifestFactsActivityInput input);

    @ActivityMethod
    String runTaint(TaintActivityInput input);

    /** Run all taint rules from a single AST-index load; returns each rule's findings key in order. */
    @ActivityMethod
    List<String> runTaintBatch(TaintBatchActivityInput input);

    @ActivityMethod
    String runManifestMisconfig(MisconfigActivityInput input);

    @ActivityMethod
    ReportArtifacts report(ReportActivityInput input);
}
