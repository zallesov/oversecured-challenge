package com.oversecured.sast.misconfig;

import static org.assertj.core.api.Assertions.assertThat;

import com.oversecured.sast.common.Severity;
import com.oversecured.sast.misconfig.model.MisconfigCheck;
import com.oversecured.sast.misconfig.model.MisconfigRuleFile;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

class MisconfigRuleLoaderTest {

    @Test
    void modelExposesRulesPlanCompatibleGetters() {
        MisconfigCheck check = new MisconfigCheck(
                "exported_provider",
                Severity.ERROR,
                "CWE-926",
                "exported-content-provider",
                "ContentProvider is exported");
        MisconfigRuleFile file = new MisconfigRuleFile(1, List.of(check));

        assertThat(file.getVersion()).isEqualTo(1);
        assertThat(file.getChecks()).containsExactly(check);
        assertThat(check.getId()).isEqualTo("exported_provider");
        assertThat(check.getSeverity()).isEqualTo(Severity.ERROR);
        assertThat(check.getCwe()).isEqualTo("CWE-926");
        assertThat(check.getKind()).isEqualTo("exported-content-provider");
        assertThat(check.getMessage()).isEqualTo("ContentProvider is exported");
    }

    @Test
    void loadsSnakeCaseYamlWithLowercaseSeverity() {
        String yaml = """
                version: 1
                checks:
                  - id: exported_without_permission
                    severity: warning
                    cwe: CWE-926
                    kind: exported-component-no-permission
                    message: "Component is exported without permission"
                """;

        MisconfigRuleFile file = MisconfigRuleLoader.load(yaml.getBytes(StandardCharsets.UTF_8));

        assertThat(file.getVersion()).isEqualTo(1);
        assertThat(file.getChecks()).hasSize(1);
        MisconfigCheck check = file.getChecks().get(0);
        assertThat(check.getId()).isEqualTo("exported_without_permission");
        assertThat(check.getSeverity()).isEqualTo(Severity.WARNING);
        assertThat(check.getKind()).isEqualTo("exported-component-no-permission");
    }
}
