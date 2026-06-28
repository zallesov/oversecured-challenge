package com.oversecured.sast.orchestrator;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

public record AnalysisPlan(
        String runId,
        ArtifactKeys keys,
        List<TaintAnalysis> taintAnalyses,
        ManifestMisconfigAnalysis manifestMisconfig,
        ReportConfig report) {

    /**
     * Rule whose file name ({@code rules/misconfig.yaml}) is reserved for the manifest-misconfig
     * analyzer. It is wired as its own branch, never as a taint rule, and is excluded when the
     * caller asks for {@code "all"} taint rules.
     */
    public static final String MISCONFIG_RULE = "misconfig";

    /** Built-in taint rules, used when no explicit rule selection is supplied. */
    public static final List<String> DEFAULT_TAINT_RULES = List.of(
            "webview",
            "pathtraversal",
            "intent-redirect",
            "file-theft",
            "login-url-injection",
            "credential-log-leak",
            "credential-intent-exfil");

    public AnalysisPlan {
        taintAnalyses = List.copyOf(taintAnalyses);
    }

    /** Plan over the built-in default taint rule set. */
    public static AnalysisPlan defaultPlan(String runId) {
        return forRules(runId, DEFAULT_TAINT_RULES);
    }

    /**
     * Build a plan running exactly the named taint rules. A rule name is the rule file's base name
     * (no {@code .yaml}); {@code "foo"} maps to artifact key {@code rules/foo.yaml} and findings key
     * {@code <root>/findings-foo.json}. The {@code misconfig} branch always runs regardless.
     */
    public static AnalysisPlan forRules(String runId, List<String> taintRuleNames) {
        ArtifactKeys keys = ArtifactKeys.forRun(runId);
        if (taintRuleNames.isEmpty()) {
            throw new IllegalArgumentException("at least one taint rule must be selected");
        }
        List<TaintAnalysis> taints = new ArrayList<>();
        for (String name : new LinkedHashSet<>(taintRuleNames)) {
            requireRuleName(name);
            if (MISCONFIG_RULE.equals(name)) {
                throw new IllegalArgumentException(
                        "'" + MISCONFIG_RULE + "' is the manifest-misconfig rule, not a taint rule");
            }
            taints.add(new TaintAnalysis(
                    name,
                    "rules/" + name + ".yaml",
                    keys.rootKey() + "/findings-" + name + ".json"));
        }
        return new AnalysisPlan(
                runId,
                keys,
                taints,
                new ManifestMisconfigAnalysis(
                        "manifest-misconfig",
                        "rules/" + MISCONFIG_RULE + ".yaml",
                        keys.rootKey() + "/findings-" + MISCONFIG_RULE + ".json"),
                new ReportConfig(
                        keys.rootKey() + "/report.html",
                        keys.rootKey() + "/report.sarif",
                        keys.rootKey() + "/ai-triage.json",
                        keys.rootKey() + "/ai-triage.md",
                        keys.rootKey() + "/findings-ai-triage.json"));
    }

    private static void requireRuleName(String name) {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("rule name must not be blank");
        }
        // A rule name is a single path segment; reject anything that could escape rules/.
        if (name.contains("/") || name.contains("\\") || name.contains("..")) {
            throw new IllegalArgumentException("invalid rule name: " + name);
        }
    }

    public List<String> findingsKeysForReporter() {
        List<String> keys = new ArrayList<>();
        for (TaintAnalysis analysis : taintAnalyses) {
            keys.add(analysis.findingsKey());
        }
        keys.add(manifestMisconfig.findingsKey());
        return List.copyOf(keys);
    }

    public record TaintAnalysis(String name, String rulePath, String findingsKey) {
    }

    public record ManifestMisconfigAnalysis(String name, String rulePath, String findingsKey) {
    }

    public record ReportConfig(
            String htmlKey,
            String sarifKey,
            String aiTriageJsonKey,
            String aiTriageMdKey,
            String aiTriageFindingsKey) {
    }
}
