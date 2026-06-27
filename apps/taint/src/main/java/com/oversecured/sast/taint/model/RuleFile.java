package com.oversecured.sast.taint.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/** Top-level YAML rule document: version + rules. */
public final class RuleFile {
    private final int version;
    private final List<Rule> rules;

    @JsonCreator
    public RuleFile(
            @JsonProperty("version") int version,
            @JsonProperty("rules") List<Rule> rules) {
        this.version = version;
        this.rules = rules == null ? List.of() : List.copyOf(rules);
    }

    public int getVersion() {
        return version;
    }

    public List<Rule> getRules() {
        return rules;
    }
}
