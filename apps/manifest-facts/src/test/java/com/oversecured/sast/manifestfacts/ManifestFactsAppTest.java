package com.oversecured.sast.manifestfacts;

import com.oversecured.sast.common.Json;
import com.oversecured.sast.common.ManifestFacts;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.assertj.core.api.Assertions.assertThat;

class ManifestFactsAppTest {

    @TempDir
    Path tempDir;

    private Path fixture(String name) throws Exception {
        return Paths.get(getClass().getResource("/manifests/" + name).toURI());
    }

    @Test
    void extract_writesFactsJsonThatDeserializesIntoSharedManifestFacts() throws Exception {
        Path out = tempDir.resolve("nested/facts.json");

        ManifestFacts returned = new ManifestFactsApp().extract(fixture("deeplink-data.xml"), out);
        ManifestFacts fromDisk = Json.read(Files.readAllBytes(out), ManifestFacts.class);

        assertThat(fromDisk).isEqualTo(returned);
        assertThat(fromDisk.packageName()).isEqualTo("oversecured.deeplink");
        assertThat(Files.readString(out)).contains("\"packageName\"");
        assertThat(Files.readString(out)).contains("\"intentFilters\"");
    }

    @Test
    void extract_malformedXmlDoesNotWriteFactsJson() throws Exception {
        Path badManifest = tempDir.resolve("AndroidManifest.xml");
        Path out = tempDir.resolve("facts.json");
        Files.writeString(badManifest, "<manifest><application></manifest>");

        org.assertj.core.api.Assertions.assertThatThrownBy(
                        () -> new ManifestFactsApp().extract(badManifest, out))
                .isInstanceOf(ManifestFactsException.class)
                .hasMessageContaining("AndroidManifest.xml");
        assertThat(out).doesNotExist();
    }
}
