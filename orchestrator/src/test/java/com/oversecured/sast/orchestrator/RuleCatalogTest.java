package com.oversecured.sast.orchestrator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class RuleCatalogTest {

    private static Path seedRules(Path dir) throws IOException {
        Files.writeString(dir.resolve("webview.yaml"), "version: 1\n");
        Files.writeString(dir.resolve("pathtraversal.yaml"), "version: 1\n");
        Files.writeString(dir.resolve("misconfig.yaml"), "version: 1\n");
        Files.writeString(dir.resolve("README.md"), "not a rule\n");
        return dir;
    }

    @Test
    void allExpandsToEveryYamlSortedExceptMisconfig(@TempDir Path dir) throws IOException {
        RuleCatalog catalog = new RuleCatalog(seedRules(dir));

        assertThat(catalog.resolve("all"))
                .containsExactly("pathtraversal", "webview");
    }

    @Test
    void blankOrNullSelectionDefaultsToAll(@TempDir Path dir) throws IOException {
        RuleCatalog catalog = new RuleCatalog(seedRules(dir));

        assertThat(catalog.resolve(null)).containsExactly("pathtraversal", "webview");
        assertThat(catalog.resolve("  ")).containsExactly("pathtraversal", "webview");
    }

    @Test
    void explicitSelectionPreservesOrderAndIsNotListed(@TempDir Path dir) throws IOException {
        RuleCatalog catalog = new RuleCatalog(seedRules(dir));

        // commas and whitespace both separate; order preserved as given
        assertThat(catalog.resolve("file-theft, webview  pathtraversal"))
                .containsExactly("file-theft", "webview", "pathtraversal");
    }

    @Test
    void anyAllTokenInListExpandsToEverything(@TempDir Path dir) throws IOException {
        RuleCatalog catalog = new RuleCatalog(seedRules(dir));

        assertThat(catalog.resolve("webview,all")).containsExactly("pathtraversal", "webview");
    }

    @Test
    void missingDirectoryFails(@TempDir Path dir) {
        RuleCatalog catalog = new RuleCatalog(dir.resolve("nope"));

        assertThatThrownBy(catalog::allTaintRuleNames)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("rules directory not found");
    }
}
