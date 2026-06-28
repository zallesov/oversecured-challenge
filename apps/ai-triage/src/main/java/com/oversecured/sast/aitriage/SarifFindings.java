package com.oversecured.sast.aitriage;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Parses the reporter's SARIF v2.1.0 document into triage findings. */
public final class SarifFindings {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public List<TriageFinding> parse(Path sarif) throws IOException {
        JsonNode root = MAPPER.readTree(Files.readString(sarif));
        List<TriageFinding> findings = new ArrayList<>();
        JsonNode runs = root.path("runs");
        for (JsonNode run : runs) {
            Map<String, JsonNode> rulesById = indexRules(run.path("tool").path("driver").path("rules"));
            for (JsonNode result : run.path("results")) {
                findings.add(toFinding(result, rulesById));
            }
        }
        return findings;
    }

    private Map<String, JsonNode> indexRules(JsonNode rules) {
        Map<String, JsonNode> byId = new HashMap<>();
        for (JsonNode rule : rules) {
            byId.put(rule.path("id").asText(""), rule);
        }
        return byId;
    }

    private TriageFinding toFinding(JsonNode result, Map<String, JsonNode> rulesById) {
        String ruleId = result.path("ruleId").asText("");
        String level = result.path("level").asText("");
        String message = result.path("message").path("text").asText("");

        List<TriageFlowStep> flow = new ArrayList<>();
        JsonNode tfLocations = result.path("codeFlows").path(0)
                .path("threadFlows").path(0).path("locations");
        for (JsonNode loc : tfLocations) {
            JsonNode location = loc.path("location");
            flow.add(new TriageFlowStep(
                    uri(location),
                    startLine(location),
                    location.path("message").path("text").asText("")));
        }

        FindingRef ref;
        if (!flow.isEmpty()) {
            ref = new FindingRef(ruleId, flow.get(0).file(), flow.get(0).line());
        } else {
            JsonNode primary = result.path("locations").path(0);
            ref = new FindingRef(ruleId, uri(primary), startLine(primary));
        }

        JsonNode rule = rulesById.get(ruleId);
        String cwe = rule == null ? null : textOrNull(rule.path("properties").path("cwe"));
        String owasp = rule == null ? null : textOrNull(rule.path("properties").path("owaspMobile"));

        return new TriageFinding(ruleId, level, message, cwe, owasp, flow, ref);
    }

    private String uri(JsonNode location) {
        return location.path("physicalLocation").path("artifactLocation").path("uri").asText("");
    }

    private int startLine(JsonNode location) {
        return location.path("physicalLocation").path("region").path("startLine").asInt(-1);
    }

    private String textOrNull(JsonNode node) {
        return node.isMissingNode() || node.isNull() ? null : node.asText();
    }
}
