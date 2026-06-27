package com.oversecured.sast.taint.rules;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.oversecured.sast.taint.model.Rule;
import com.oversecured.sast.taint.model.RuleFile;
import com.oversecured.sast.taint.model.SanitizerSpec;
import com.oversecured.sast.taint.model.SinkSpec;
import com.oversecured.sast.taint.model.SourceSpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Loads and validates external YAML taint rule files. */
public final class RuleLoader {

    private final ObjectMapper mapper = new ObjectMapper(new YAMLFactory())
            .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_ENUMS, true);

    public RuleFile load(Path rulePath) {
        RuleFile file;
        try {
            file = mapper.readValue(Files.readAllBytes(rulePath), RuleFile.class);
        } catch (IOException e) {
            throw new RuntimeException("Failed to read rule file: " + rulePath, e);
        }
        validate(file, rulePath);
        return file;
    }

    private void validate(RuleFile file, Path rulePath) {
        if (file.getVersion() != 1) {
            throw new IllegalArgumentException(
                    "Unsupported rule version " + file.getVersion() + " in " + rulePath);
        }
        if (file.getRules().isEmpty()) {
            throw new IllegalArgumentException("Rule file has no rules: " + rulePath);
        }
        for (Rule rule : file.getRules()) {
            validateRule(rule, rulePath);
        }
    }

    private void validateRule(Rule rule, Path rulePath) {
        requireNonBlank(rule.getId(), "rule id", rulePath);
        requireNonBlank(rule.getVulnerabilityClass(), "vulnerability_class", rulePath);
        requireNonBlank(rule.getMessage(), "message", rulePath);
        if (rule.getSources().isEmpty()) {
            throw new IllegalArgumentException("Rule " + rule.getId() + " has no sources in " + rulePath);
        }
        if (rule.getSinks().isEmpty()) {
            throw new IllegalArgumentException("Rule " + rule.getId() + " has no sinks in " + rulePath);
        }
        for (SinkSpec sink : rule.getSinks()) {
            if (sink.getTaintedArgs().isEmpty()) {
                throw new IllegalArgumentException(
                        "Sink " + sink.getSignature() + " has no tainted_args in " + rulePath);
            }
            RuleSignatures.parseMethod(sink.getSignature());
        }
        for (SourceSpec source : rule.getSources()) {
            RuleSignatures.parseMethod(source.getSignature());
        }
        for (SanitizerSpec sanitizer : rule.getSanitizers()) {
            RuleSignatures.parseMethod(sanitizer.getSignature());
        }
        for (String propagator : rule.getPropagators()) {
            RuleSignatures.parseMethod(propagator);
        }
    }

    private void requireNonBlank(String value, String field, Path rulePath) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Missing " + field + " in " + rulePath);
        }
    }
}
