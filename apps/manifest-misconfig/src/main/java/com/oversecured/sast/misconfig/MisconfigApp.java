package com.oversecured.sast.misconfig;

import com.oversecured.sast.common.FindingsDoc;
import com.oversecured.sast.common.Json;
import com.oversecured.sast.common.ManifestFacts;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public final class MisconfigApp {

    public FindingsDoc analyze(Path factsJson, Path ruleYaml, Path findingsJson) throws IOException {
        ManifestFacts facts = Json.read(Files.readAllBytes(factsJson), ManifestFacts.class);
        var rules = MisconfigRuleLoader.load(ruleYaml);
        var findings = new MisconfigAnalyzer().analyze(facts, rules);

        Path parent = findingsJson.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.write(findingsJson, Json.writeBytes(findings));
        return findings;
    }
}
