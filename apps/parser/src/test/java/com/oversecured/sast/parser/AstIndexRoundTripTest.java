package com.oversecured.sast.parser;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AstIndexRoundTripTest {

    private static Path fixture(String name) {
        return Paths.get("src", "test", "resources", "fixtures", name);
    }

    @Test
    void saveThenLoadPreservesUnitCount(@TempDir Path indexDir) {
        AstIndex built = AstIndex.build(fixture("simple"));
        built.save(indexDir);

        assertThat(Files.exists(indexDir.resolve("index-meta.json"))).isTrue();

        AstIndex loaded = AstIndex.load(indexDir);
        assertThat(loaded.units()).hasSameSizeAs(built.units());
        assertThat(loaded.units())
            .extracting(cu -> cu.getPrimaryTypeName().orElseThrow())
            .containsExactlyInAnyOrderElementsOf(
                built.units().stream()
                    .map(cu -> cu.getPrimaryTypeName().orElseThrow())
                    .toList());
    }
}
