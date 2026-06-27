package com.oversecured.sast.orchestrator.activities;

import io.temporal.activity.ActivityInterface;
import io.temporal.activity.ActivityMethod;

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

    @ActivityMethod
    String runManifestMisconfig(MisconfigActivityInput input);

    @ActivityMethod
    ReportArtifacts report(ReportActivityInput input);
}
