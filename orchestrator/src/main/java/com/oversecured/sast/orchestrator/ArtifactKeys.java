package com.oversecured.sast.orchestrator;

import java.util.regex.Pattern;

public record ArtifactKeys(
        String runId,
        String rootKey,
        String sourcesDirKey,
        String manifestKey,
        String astIndexDirKey,
        String factsKey) {

    private static final Pattern RUN_ID = Pattern.compile("[A-Za-z0-9._-]+");

    public static ArtifactKeys forRun(String runId) {
        if (runId == null || !RUN_ID.matcher(runId).matches()) {
            throw new IllegalArgumentException("runId must match [A-Za-z0-9._-]+");
        }
        String root = "runs/" + runId;
        return new ArtifactKeys(
                runId,
                root,
                root + "/sources",
                root + "/sources/AndroidManifest.xml",
                root + "/ast-index",
                root + "/facts.json");
    }
}
