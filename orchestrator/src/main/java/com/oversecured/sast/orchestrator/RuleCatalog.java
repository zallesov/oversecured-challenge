package com.oversecured.sast.orchestrator;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/** Resolves a rule selection (explicit names or the {@code "all"} keyword) against a rules directory. */
public final class RuleCatalog {

    /** The keyword that selects every taint rule found in the rules directory. */
    public static final String ALL = "all";

    private final Path rulesDir;

    public RuleCatalog(Path rulesDir) {
        this.rulesDir = rulesDir;
    }

    /**
     * Resolve a comma/space-separated selection into concrete taint rule names. {@code "all"}
     * (the default) expands to every {@code *.yaml} in the rules directory except the reserved
     * {@link AnalysisPlan#MISCONFIG_RULE} file. Explicit names are returned as given (order preserved).
     */
    public List<String> resolve(String selection) {
        List<String> tokens = split(selection);
        if (tokens.isEmpty() || tokens.stream().anyMatch(ALL::equalsIgnoreCase)) {
            return allTaintRuleNames();
        }
        return tokens;
    }

    /** Every taint rule file base name in the directory, sorted, excluding the misconfig rule. */
    public List<String> allTaintRuleNames() {
        if (!Files.isDirectory(rulesDir)) {
            throw new IllegalArgumentException("rules directory not found: " + rulesDir);
        }
        try (Stream<Path> entries = Files.list(rulesDir)) {
            return entries
                    .filter(Files::isRegularFile)
                    .map(p -> p.getFileName().toString())
                    .filter(n -> n.endsWith(".yaml"))
                    .map(n -> n.substring(0, n.length() - ".yaml".length()))
                    .filter(n -> !AnalysisPlan.MISCONFIG_RULE.equals(n))
                    .sorted()
                    .toList();
        } catch (IOException e) {
            throw new UncheckedIOException("failed to list rules directory: " + rulesDir, e);
        }
    }

    private static List<String> split(String selection) {
        List<String> out = new ArrayList<>();
        if (selection == null) {
            return out;
        }
        for (String part : selection.split("[,\\s]+")) {
            String trimmed = part.trim();
            if (!trimmed.isEmpty()) {
                out.add(trimmed);
            }
        }
        return out;
    }
}
