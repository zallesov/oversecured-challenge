package com.oversecured.sast.common;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ManifestFactsRoundTripTest {

    @Test
    void manifestFactsSurviveJsonRoundTrip() {
        ManifestFacts original = new ManifestFacts(
                "oversecured.ovaa",
                List.of(new ComponentFact(
                        "oversecured.ovaa.activities.WebViewActivity",
                        "activity",
                        true,
                        List.of(new IntentFilterFact(
                                List.of("android.intent.action.VIEW"),
                                List.of("oversecured"),
                                List.of("ovaa"))),
                        false,
                        null)),
                List.of("android.permission.INTERNET"));

        byte[] json = Json.writeBytes(original);
        ManifestFacts back = Json.read(json, ManifestFacts.class);

        assertThat(back).isEqualTo(original);
        assertThat(back.components().get(0).exported()).isTrue();
        assertThat(back.components().get(0).type()).isEqualTo("activity");
        assertThat(back.components().get(0).intentFilters().get(0).schemes()).containsExactly("oversecured");
    }
}
