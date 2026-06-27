package com.oversecured.sast.orchestrator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.oversecured.sast.orchestrator.activities.ActivityPathResolver;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ActivityPathResolverTest {

    @Test
    void resolvesArtifactKeysUnderRoot(@TempDir Path root) {
        ActivityPathResolver resolver = new ActivityPathResolver(root);

        assertThat(resolver.resolveArtifactKey("runs/r1/report.html"))
                .isEqualTo(root.resolve("runs/r1/report.html").toAbsolutePath().normalize());
    }

    @Test
    void rejectsAbsoluteKeys(@TempDir Path root) {
        ActivityPathResolver resolver = new ActivityPathResolver(root);

        assertThatThrownBy(() -> resolver.resolveArtifactKey("/tmp/report.html"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("artifact key");
    }

    @Test
    void rejectsParentDirectoryTraversal(@TempDir Path root) {
        ActivityPathResolver resolver = new ActivityPathResolver(root);

        assertThatThrownBy(() -> resolver.resolveArtifactKey("runs/r1/../../escape.txt"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("artifact key");
    }
}
