package com.oversecured.sast.misconfig;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import com.oversecured.sast.misconfig.model.MisconfigRuleFile;
import java.nio.file.Files;
import java.nio.file.Path;

public final class MisconfigRuleLoader {
    private static final ObjectMapper YAML = YAMLMapper.builder()
            .propertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .enable(MapperFeature.ACCEPT_CASE_INSENSITIVE_ENUMS)
            .build();

    private MisconfigRuleLoader() {
    }

    public static MisconfigRuleFile load(Path path) {
        try {
            return load(Files.readAllBytes(path));
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to read misconfig rule file: " + path, e);
        }
    }

    public static MisconfigRuleFile load(byte[] yaml) {
        try {
            MisconfigRuleFile file = YAML.readValue(yaml, MisconfigRuleFile.class);
            validate(file);
            return file;
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse misconfig rule YAML", e);
        }
    }

    private static void validate(MisconfigRuleFile file) {
        if (file == null) {
            throw new IllegalArgumentException("misconfig rule file is empty");
        }
        if (file.getVersion() != 1) {
            throw new IllegalArgumentException("Unsupported misconfig rule version: " + file.getVersion());
        }
        if (file.getChecks() == null || file.getChecks().isEmpty()) {
            throw new IllegalArgumentException("misconfig rule file must contain at least one check");
        }
        for (var check : file.getChecks()) {
            if (check == null || isBlank(check.getId()) || check.getSeverity() == null || isBlank(check.getCwe())
                    || isBlank(check.getKind()) || isBlank(check.getMessage())) {
                throw new IllegalArgumentException("misconfig check has missing required fields");
            }
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
