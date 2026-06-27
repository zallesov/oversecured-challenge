package com.oversecured.sast.taint;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.oversecured.sast.common.FindingsDoc;
import java.util.List;
import org.junit.jupiter.api.Test;

class BuildSmokeTest {
    @Test
    void dependenciesAreAvailable() {
        assertThat(new YAMLFactory()).isNotNull();
        assertThat(new FindingsDoc("taint-engine", List.of()).analyzer()).isEqualTo("taint-engine");
    }
}
