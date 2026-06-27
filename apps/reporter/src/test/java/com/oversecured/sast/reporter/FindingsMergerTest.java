package com.oversecured.sast.reporter;

import static org.assertj.core.api.Assertions.assertThat;

import com.oversecured.sast.common.Finding;
import com.oversecured.sast.common.FlowStep;
import com.oversecured.sast.common.Severity;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import org.junit.jupiter.api.Test;

class FindingsMergerTest {

    @Test
    void sharedModel_isReachableFromReporterModule() {
        Finding f = new Finding(
                "R1", "webview-open-redirect", Severity.ERROR, "msg", "CWE-601", "M1",
                List.of(new FlowStep("A.java", 10, "source")), List.of("note"));
        assertThat(f.ruleId()).isEqualTo("R1");
        assertThat(f.severity()).isEqualTo(Severity.ERROR);
        assertThat(f.flow()).hasSize(1);
        assertThat(f.flow().get(0).line()).isEqualTo(10);
    }

    private Path fixture(String name) throws Exception {
        return Paths.get(getClass().getResource("/fixtures/" + name).toURI());
    }

    @Test
    void merge_concatenatesAllFindingsInFileOrder() throws Exception {
        List<Finding> merged = new FindingsMerger()
                .merge(List.of(fixture("findings-taint.json"), fixture("findings-misconfig.json")));

        assertThat(merged).hasSize(2);
        assertThat(merged.get(0).ruleId()).isEqualTo("ANDROID_WEBVIEW_INTENT_LOADURL");
        assertThat(merged.get(0).severity()).isEqualTo(Severity.ERROR);
        assertThat(merged.get(0).flow()).hasSize(4);
        assertThat(merged.get(0).flow().get(0).line()).isEqualTo(47);
        assertThat(merged.get(0).notes()).containsExactly(
                "incomplete-sanitizer: host.endsWith(\"example.com\") bypassable");
        assertThat(merged.get(1).ruleId()).isEqualTo("ANDROID_EXPORTED_NO_PERMISSION");
        assertThat(merged.get(1).severity()).isEqualTo(Severity.WARNING);
    }

    @Test
    void merge_emptyInput_returnsEmptyList() throws Exception {
        assertThat(new FindingsMerger().merge(List.of())).isEmpty();
    }
}
