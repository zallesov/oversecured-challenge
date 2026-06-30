package com.oversecured.sast.orchestrator;

import com.oversecured.sast.orchestrator.workflow.ActivityNodeIds;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ActivityNodeIdsTest {

    @Test
    void decompileMapsToDecompile() {
        assertThat(ActivityNodeIds.nodeIdForActivityType("Decompile")).isEqualTo("decompile");
    }

    @Test
    void parseSourcesMapsToparse() {
        assertThat(ActivityNodeIds.nodeIdForActivityType("ParseSources")).isEqualTo("parse");
    }

    @Test
    void extractManifestFactsMapsToManifestFacts() {
        assertThat(ActivityNodeIds.nodeIdForActivityType("ExtractManifestFacts")).isEqualTo("manifest-facts");
    }

    @Test
    void runTaintBatchMapsToTaint() {
        assertThat(ActivityNodeIds.nodeIdForActivityType("RunTaintBatch")).isEqualTo("taint");
    }

    @Test
    void runManifestMisconfigMapsToManifestMisconfig() {
        assertThat(ActivityNodeIds.nodeIdForActivityType("RunManifestMisconfig")).isEqualTo("manifest-misconfig");
    }

    @Test
    void reportMapsToReport() {
        assertThat(ActivityNodeIds.nodeIdForActivityType("Report")).isEqualTo("report");
    }

    @Test
    void aiTriageMapsToAiTriage() {
        assertThat(ActivityNodeIds.nodeIdForActivityType("AiTriage")).isEqualTo("ai-triage");
    }

    @Test
    void unknownTypeMapsTtItself() {
        assertThat(ActivityNodeIds.nodeIdForActivityType("SomethingUnknown")).isEqualTo("SomethingUnknown");
    }
}
