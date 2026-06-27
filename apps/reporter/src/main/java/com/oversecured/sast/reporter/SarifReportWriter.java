package com.oversecured.sast.reporter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.oversecured.sast.common.Finding;
import com.oversecured.sast.common.FlowStep;
import com.oversecured.sast.common.Severity;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Builds a SARIF v2.1.0 document from merged findings. */
public final class SarifReportWriter {

    private static final ObjectMapper MAPPER = FindingsMerger.mapper();
    private static final String SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";

    public ObjectNode toSarif(List<Finding> findings) {
        Map<String, Finding> ruleById = new LinkedHashMap<>();
        for (Finding finding : findings) {
            ruleById.putIfAbsent(finding.ruleId(), finding);
        }
        List<String> ruleOrder = new ArrayList<>(ruleById.keySet());

        ObjectNode root = MAPPER.createObjectNode();
        root.put("version", "2.1.0");
        root.put("$schema", SCHEMA);

        ArrayNode runs = root.putArray("runs");
        ObjectNode run = runs.addObject();

        ObjectNode driver = run.putObject("tool").putObject("driver");
        driver.put("name", "android-taint-sast");
        driver.put("version", "0.1.0");
        driver.put("informationUri", "https://github.com/oversecured/challenge");
        ArrayNode rules = driver.putArray("rules");
        for (String ruleId : ruleOrder) {
            Finding finding = ruleById.get(ruleId);
            ObjectNode rule = rules.addObject();
            rule.put("id", finding.ruleId());
            rule.put("name", finding.vulnerabilityClass());
            rule.putObject("shortDescription").put("text", finding.message());
            rule.putObject("defaultConfiguration").put("level", level(finding.severity()));
            ObjectNode props = rule.putObject("properties");
            props.put("cwe", finding.cwe());
            props.put("owaspMobile", finding.owaspMobile());
            props.put("vulnerabilityClass", finding.vulnerabilityClass());
        }

        ArrayNode results = run.putArray("results");
        for (Finding finding : findings) {
            ObjectNode result = results.addObject();
            result.put("ruleId", finding.ruleId());
            result.put("ruleIndex", ruleOrder.indexOf(finding.ruleId()));
            result.put("level", level(finding.severity()));
            result.putObject("message").put("text", finding.message());

            if (finding.flow() != null && !finding.flow().isEmpty()) {
                FlowStep sink = finding.flow().get(finding.flow().size() - 1);
                result.putArray("locations").add(physicalLocationWrapper(sink));

                ArrayNode tfLocations = result.putArray("codeFlows")
                        .addObject().putArray("threadFlows")
                        .addObject().putArray("locations");
                for (FlowStep step : finding.flow()) {
                    ObjectNode loc = tfLocations.addObject();
                    ObjectNode location = loc.putObject("location");
                    addPhysicalLocation(location, step);
                    location.putObject("message").put("text", step.label());
                }
            }
        }

        return root;
    }

    public String toSarifJson(List<Finding> findings) throws JsonProcessingException {
        return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(toSarif(findings));
    }

    private ObjectNode physicalLocationWrapper(FlowStep step) {
        ObjectNode wrapper = MAPPER.createObjectNode();
        addPhysicalLocation(wrapper, step);
        return wrapper;
    }

    private void addPhysicalLocation(ObjectNode parent, FlowStep step) {
        ObjectNode physical = parent.putObject("physicalLocation");
        physical.putObject("artifactLocation").put("uri", step.file());
        physical.putObject("region").put("startLine", step.line());
    }

    private static String level(Severity severity) {
        return switch (severity) {
            case ERROR -> "error";
            case WARNING -> "warning";
            case NOTE -> "note";
        };
    }
}
