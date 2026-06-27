package com.oversecured.sast.misconfig;

import static org.assertj.core.api.Assertions.assertThat;

import com.oversecured.sast.common.Finding;
import com.oversecured.sast.common.FindingsDoc;
import com.oversecured.sast.common.Json;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

class MisconfigCommandTest {

    @Test
    void commandNameIsMscan() {
        CommandLine cmd = new CommandLine(new MisconfigCommand());
        assertThat(cmd.getCommandName()).isEqualTo("mscan");
    }

    @Test
    void commandWritesFindingsJson() throws Exception {
        Path dir = Files.createTempDirectory("mscan-test");
        Path facts = dir.resolve("facts.json");
        Path rule = dir.resolve("misconfig.yaml");
        Path out = dir.resolve("findings.json");

        Files.writeString(facts, """
                {
                  "packageName": "oversecured.ovaa",
                  "components": [
                    {"name":"oversecured.ovaa.DeeplinkActivity","type":"activity","exported":true,
                     "intentFilters":[],"grantUriPermissions":false,"permission":null}
                  ],
                  "permissions": []
                }
                """);
        Files.writeString(rule, """
                version: 1
                checks:
                  - id: exported_without_permission
                    severity: warning
                    cwe: CWE-926
                    kind: exported-component-no-permission
                    message: "Component is exported without permission"
                """);

        int exit = new CommandLine(new MisconfigCommand()).execute(
                "--facts", facts.toString(),
                "--rule", rule.toString(),
                "--out", out.toString());

        assertThat(exit).isEqualTo(0);
        assertThat(Files.exists(out)).isTrue();
        FindingsDoc doc = Json.read(Files.readAllBytes(out), FindingsDoc.class);
        assertThat(doc.analyzer()).isEqualTo("manifest-misconfig");
        assertThat(doc.findings()).extracting(Finding::ruleId)
                .containsExactly("exported_without_permission");
    }

    @Test
    void commandRunsAgainstRepositoryMisconfigYaml() throws Exception {
        Path rule = findRepoRoot().resolve("rules/misconfig.yaml");
        Path dir = Files.createTempDirectory("mscan-real-rules");
        Path facts = dir.resolve("facts.json");
        Path out = dir.resolve("findings-misconfig.json");

        Files.writeString(facts, """
                {
                  "packageName": "oversecured.ovaa",
                  "components": [
                    {"name":"oversecured.ovaa.DeeplinkActivity","type":"activity","exported":true,
                     "intentFilters":[{"actions":["android.intent.action.VIEW"],"schemes":["https"],"hosts":["*.example.com"]}],
                     "grantUriPermissions":false,"permission":null},
                    {"name":"oversecured.ovaa.FileProvider","type":"provider","exported":true,
                     "intentFilters":[],"permission":null,"grantUriPermissions":true}
                  ],
                  "permissions": []
                }
                """);

        int exit = new CommandLine(new MisconfigCommand()).execute(
                "--facts", facts.toString(),
                "--rule", rule.toString(),
                "--out", out.toString());

        assertThat(exit).isEqualTo(0);
        FindingsDoc doc = Json.read(Files.readAllBytes(out), FindingsDoc.class);
        assertThat(doc.findings()).extracting(Finding::ruleId)
                .contains(
                        "exported_without_permission",
                        "exported_provider",
                        "provider_grant_uri_permissions",
                        "weak_host_validation");
    }

    private static Path findRepoRoot() {
        Path dir = Path.of("").toAbsolutePath();
        while (dir != null) {
            if (Files.isRegularFile(dir.resolve("settings.gradle"))) {
                return dir;
            }
            dir = dir.getParent();
        }
        throw new IllegalStateException("could not locate repo root");
    }
}
