package com.oversecured.sast.aitriage;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class LangChainTriageEngineTest {

    @Test
    void createReturnsNullWithoutApiKey(@TempDir Path dir) {
        assertThat(LangChainTriageEngine.create(null, "https://x", "m", dir)).isNull();
        assertThat(LangChainTriageEngine.create("  ", "https://x", "m", dir)).isNull();
    }

    @Test
    void createBuildsEngineWithApiKeyWithoutCallingNetwork(@TempDir Path dir) {
        TriageEngine engine = LangChainTriageEngine.create("sk-test", "https://x", "test-model", dir);
        assertThat(engine).isNotNull();
        assertThat(engine.modelName()).isEqualTo("test-model");
    }

    @Test
    void extractsJsonFromFencedProseResponse() {
        String reply = "Here is my analysis.\n\n```json\n{ \"summary\": \"s\", \"items\": [] }\n```\nDone.";
        assertThat(LangChainTriageEngine.extractJson(reply)).isEqualTo("{ \"summary\": \"s\", \"items\": [] }");
    }

    @Test
    void extractsBareJsonObjectFromProse() {
        String reply = "Reasoning first. { \"summary\": \"s\", \"items\": [] } trailing words.";
        assertThat(LangChainTriageEngine.extractJson(reply)).isEqualTo("{ \"summary\": \"s\", \"items\": [] }");
    }
}
