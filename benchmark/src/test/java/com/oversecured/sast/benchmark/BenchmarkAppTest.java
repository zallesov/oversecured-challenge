package com.oversecured.sast.benchmark;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class BenchmarkAppTest {
    @Test
    void exposesHelloWorldStub() {
        assertThat(BenchmarkApp.message())
                .isEqualTo("Hello World from benchmark");
    }
}
