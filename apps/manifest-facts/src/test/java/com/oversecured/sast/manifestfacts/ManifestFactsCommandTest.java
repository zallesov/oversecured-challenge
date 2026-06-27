package com.oversecured.sast.manifestfacts;

import com.oversecured.sast.common.Json;
import com.oversecured.sast.common.ManifestFacts;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import static org.assertj.core.api.Assertions.assertThat;

class ManifestFactsCommandTest {

    @TempDir
    Path tempDir;

    private Path fixture(String name) throws Exception {
        return Paths.get(getClass().getResource("/manifests/" + name).toURI());
    }

    @Test
    void command_writesFactsJsonFromManifestArgument() throws Exception {
        Path out = tempDir.resolve("facts.json");

        int exit = new CommandLine(new ManifestFactsCommand()).execute(
                "--manifest", fixture("deeplink-data.xml").toString(),
                "--out", out.toString());

        assertThat(exit).isEqualTo(0);
        ManifestFacts facts = Json.read(Files.readAllBytes(out), ManifestFacts.class);
        assertThat(facts.packageName()).isEqualTo("oversecured.deeplink");
        assertThat(facts.components()).hasSize(1);
    }

    @Test
    void command_missingManifestReturnsUsageError() {
        int exit = new CommandLine(new ManifestFactsCommand()).execute("--out", "facts.json");

        assertThat(exit).isEqualTo(CommandLine.ExitCode.USAGE);
    }
}
