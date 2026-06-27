package com.oversecured.sast.misconfig;

import static org.assertj.core.api.Assertions.assertThat;

import com.oversecured.sast.common.ComponentFact;
import com.oversecured.sast.common.Finding;
import com.oversecured.sast.common.FindingsDoc;
import com.oversecured.sast.common.IntentFilterFact;
import com.oversecured.sast.common.ManifestFacts;
import com.oversecured.sast.common.Severity;
import com.oversecured.sast.misconfig.model.MisconfigCheck;
import com.oversecured.sast.misconfig.model.MisconfigRuleFile;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class MisconfigAnalyzerTest {

    @Test
    void reportsExportedComponentWithoutPermission() {
        ManifestFacts facts = new ManifestFacts(
                "oversecured.ovaa",
                List.of(new ComponentFact("oversecured.ovaa.DeeplinkActivity", "activity", true, List.of(), false, null)),
                List.of());
        FindingsDoc doc = new MisconfigAnalyzer().analyze(facts, rules("exported_without_permission"));

        assertThat(doc.analyzer()).isEqualTo("manifest-misconfig");
        assertThat(doc.findings()).extracting(Finding::ruleId).containsExactly("exported_without_permission");
        Finding finding = doc.findings().get(0);
        assertThat(finding.severity()).isEqualTo(Severity.WARNING);
        assertThat(finding.vulnerabilityClass()).isEqualTo("exported-component-no-permission");
        assertThat(finding.flow().get(0).label()).contains("oversecured.ovaa.DeeplinkActivity");
    }

    @Test
    void reportsExportedProviderAndGrantUriPermissions() {
        ManifestFacts facts = new ManifestFacts(
                "oversecured.ovaa",
                List.of(new ComponentFact("oversecured.ovaa.FileProvider", "provider", true, List.of(), true, null)),
                List.of());

        FindingsDoc doc = new MisconfigAnalyzer().analyze(
                facts,
                rules("exported_provider", "provider_grant_uri_permissions"));

        assertThat(doc.findings()).extracting(Finding::ruleId)
                .containsExactly("exported_provider", "provider_grant_uri_permissions");
    }

    @Test
    void reportsWeakHostValidationFromManifestFacts() {
        ManifestFacts facts = new ManifestFacts(
                "oversecured.ovaa",
                List.of(
                        new ComponentFact(
                                "oversecured.ovaa.WildcardActivity",
                                "activity",
                                true,
                                List.of(new IntentFilterFact(
                                        List.of("android.intent.action.VIEW"),
                                        List.of("https"),
                                        List.of("*.example.com"))),
                                false,
                                null),
                        new ComponentFact(
                                "oversecured.ovaa.StrictHostActivity",
                                "activity",
                                true,
                                List.of(new IntentFilterFact(
                                        List.of("android.intent.action.VIEW"),
                                        List.of("https"),
                                        List.of("example.com"))),
                                false,
                                null)),
                List.of());

        FindingsDoc doc = new MisconfigAnalyzer().analyze(facts, rules("weak_host_validation"));

        assertThat(doc.findings()).extracting(Finding::ruleId)
                .containsExactly("weak_host_validation");
    }

    @Test
    void doesNotReportGrantUriWhenGrantFlagIsFalse() {
        ManifestFacts facts = new ManifestFacts(
                "oversecured.ovaa",
                List.of(new ComponentFact("oversecured.ovaa.FileProvider", "provider", true, List.of(), false, null)),
                List.of());

        FindingsDoc doc = new MisconfigAnalyzer().analyze(
                facts,
                rules("provider_grant_uri_permissions"));

        assertThat(doc.findings()).isEmpty();
    }

    private static MisconfigRuleFile rules(String... ids) {
        Map<String, MisconfigCheck> all = Map.of(
                "exported_without_permission", new MisconfigCheck(
                        "exported_without_permission", Severity.WARNING, "CWE-926",
                        "exported-component-no-permission", "Component is exported without permission"),
                "exported_provider", new MisconfigCheck(
                        "exported_provider", Severity.ERROR, "CWE-926",
                        "exported-content-provider", "ContentProvider is exported"),
                "provider_grant_uri_permissions", new MisconfigCheck(
                        "provider_grant_uri_permissions", Severity.WARNING, "CWE-266",
                        "provider-grant-uri-permissions", "ContentProvider grants URI permissions"),
                "weak_host_validation", new MisconfigCheck(
                        "weak_host_validation", Severity.ERROR, "CWE-601",
                        "weak-host-validation", "Weak deeplink host validation"));
        return new MisconfigRuleFile(1, Arrays.stream(ids).map(all::get).toList());
    }
}
