package com.oversecured.sast.orchestrator.activities;

import java.util.List;

/**
 * Runs several taint rules against a single load of the AST index + facts. Replaces N per-rule
 * taint activities (each of which re-parses the whole decompiled tree, and under fan-out re-parses
 * in parallel — the memory blow-up). One activity, one parse, one {@code android.jar} solver.
 */
public record TaintBatchActivityInput(String astIndexDirKey, String factsKey, List<Rule> rules) {

    public TaintBatchActivityInput {
        rules = List.copyOf(rules);
    }

    public record Rule(String name, String rulePath, String findingsKey) {
    }
}
