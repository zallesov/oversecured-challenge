package com.oversecured.sast.manifestfacts;

import com.oversecured.sast.common.ComponentFact;
import com.oversecured.sast.common.IntentFilterFact;
import com.oversecured.sast.common.ManifestFacts;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AndroidManifestFactsExtractorTest {

    @Test
    void sharedManifestFactsModelIsReachable() {
        ManifestFacts facts = new ManifestFacts(
                "oversecured.ovaa",
                List.of(new ComponentFact(
                        "oversecured.ovaa.activities.DeeplinkActivity",
                        "activity",
                        true,
                        List.of(new IntentFilterFact(
                                List.of("android.intent.action.VIEW"),
                                List.of("oversecured"),
                                List.of("ovaa"))),
                        false,
                        null)),
                List.of("android.permission.INTERNET"));

        assertThat(facts.packageName()).isEqualTo("oversecured.ovaa");
        assertThat(facts.components()).hasSize(1);
        assertThat(facts.components().get(0).exported()).isTrue();
        assertThat(facts.components().get(0).intentFilters().get(0).schemes())
                .containsExactly("oversecured");
    }

    private java.nio.file.Path fixture(String name) throws Exception {
        return java.nio.file.Paths.get(getClass().getResource("/manifests/" + name).toURI());
    }

    @Test
    void extract_readsPackageName() throws Exception {
        ManifestFacts facts = new AndroidManifestFactsExtractor()
                .extract(fixture("exported-explicit.xml"));

        assertThat(facts.packageName()).isEqualTo("oversecured.ovaa");
        assertThat(facts.components()).isEmpty();
        assertThat(facts.permissions()).isEmpty();
    }
}
