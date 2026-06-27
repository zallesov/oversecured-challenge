package com.oversecured.sast.manifestmisconfig;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class ManifestMisconfigAppTest {
    @Test
    void exposesHelloWorldStub() {
        assertThat(ManifestMisconfigApp.message())
                .isEqualTo("Hello World from manifest-misconfig");
    }
}
