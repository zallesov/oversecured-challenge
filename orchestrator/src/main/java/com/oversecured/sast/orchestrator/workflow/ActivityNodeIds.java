package com.oversecured.sast.orchestrator.workflow;

import java.util.Map;

/**
 * Maps Temporal activity type names to pipeline node IDs used in status events.
 */
public final class ActivityNodeIds {

    private static final Map<String, String> MAP = Map.of(
            "Decompile",            "decompile",
            "ParseSources",         "parse",
            "ExtractManifestFacts", "manifest-facts",
            "RunTaintBatch",        "taint",
            "RunManifestMisconfig", "manifest-misconfig",
            "Report",               "report",
            "AiTriage",             "ai-triage"
    );

    private ActivityNodeIds() {}

    /**
     * Returns the pipeline node ID for the given Temporal activity type name,
     * or the input unchanged if the type is not in the known map.
     */
    public static String nodeIdForActivityType(String activityType) {
        return MAP.getOrDefault(activityType, activityType);
    }
}
