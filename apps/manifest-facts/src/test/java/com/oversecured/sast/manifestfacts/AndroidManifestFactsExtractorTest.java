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
    void extract_readsComponents_explicitExported_relativeNames_andPermissions() throws Exception {
        ManifestFacts facts = new AndroidManifestFactsExtractor()
                .extract(fixture("exported-explicit.xml"));

        assertThat(facts.packageName()).isEqualTo("oversecured.ovaa");
        assertThat(facts.components()).extracting(ComponentFact::name)
                .containsExactly(
                        "oversecured.ovaa.activities.DeeplinkActivity",
                        "oversecured.ovaa.SyncService");

        ComponentFact activity = facts.components().get(0);
        assertThat(activity.type()).isEqualTo("activity");
        assertThat(activity.exported()).isTrue();
        assertThat(activity.permission()).isEqualTo("oversecured.ovaa.permission.INTERNAL");
        assertThat(activity.intentFilters()).isEmpty();

        ComponentFact service = facts.components().get(1);
        assertThat(service.type()).isEqualTo("service");
        assertThat(service.exported()).isFalse();
        assertThat(service.permission()).isEqualTo("oversecured.ovaa.permission.INTERNAL");
    }

    @Test
    void extract_appliesPre31DefaultExportedFromIntentFilters() throws Exception {
        ManifestFacts facts = new AndroidManifestFactsExtractor()
                .extract(fixture("exported-defaults.xml"));

        assertThat(facts.components()).extracting(ComponentFact::name, ComponentFact::exported)
                .containsExactly(
                        org.assertj.core.groups.Tuple.tuple("oversecured.defaults.FilteredActivity", true),
                        org.assertj.core.groups.Tuple.tuple("oversecured.defaults.BootReceiver", true),
                        org.assertj.core.groups.Tuple.tuple("oversecured.defaults.PlainService", false),
                        org.assertj.core.groups.Tuple.tuple("oversecured.defaults.FilesProvider", false),
                        org.assertj.core.groups.Tuple.tuple("oversecured.defaults.ExplicitFalseActivity", false));
    }

    @Test
    void extract_readsIntentFilterActionsAndDataSchemesHosts() throws Exception {
        ManifestFacts facts = new AndroidManifestFactsExtractor()
                .extract(fixture("deeplink-data.xml"));

        ComponentFact component = facts.components().get(0);
        assertThat(component.exported()).isTrue();
        assertThat(component.intentFilters()).hasSize(1);

        IntentFilterFact filter = component.intentFilters().get(0);
        assertThat(filter.actions()).containsExactly("android.intent.action.VIEW");
        assertThat(filter.schemes()).containsExactly("https", "oversecured");
        assertThat(filter.hosts()).containsExactly("example.com", "ovaa");
    }
}
