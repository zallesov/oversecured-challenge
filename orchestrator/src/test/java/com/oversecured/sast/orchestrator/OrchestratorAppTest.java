package com.oversecured.sast.orchestrator;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class OrchestratorAppTest {
    @Test
    void exposesHelloWorldStub() {
        assertThat(OrchestratorApp.message())
                .isEqualTo("Hello World from orchestrator");
    }
}
