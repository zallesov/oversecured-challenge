package com.oversecured.sast.reporter;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class ReporterAppTest {
    @Test
    void exposesHelloWorldStub() {
        assertThat(ReporterApp.message())
                .isEqualTo("Hello World from reporter");
    }
}
