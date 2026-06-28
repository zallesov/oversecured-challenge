package com.oversecured.sast.taint;

import com.github.javaparser.ast.body.MethodDeclaration;
import com.oversecured.sast.common.Finding;
import com.oversecured.sast.common.FindingsDoc;
import com.oversecured.sast.common.FlowStep;
import com.oversecured.sast.common.Json;
import com.oversecured.sast.common.ManifestFacts;
import com.oversecured.sast.parser.AstIndex;
import com.oversecured.sast.taint.flow.CandidateFinding;
import com.oversecured.sast.taint.flow.IntraProceduralAnalyzer;
import com.oversecured.sast.taint.icc.IccModel;
import com.oversecured.sast.taint.manifest.ReachabilityFilter;
import com.oversecured.sast.taint.match.RuleMatcher;
import com.oversecured.sast.taint.model.Rule;
import com.oversecured.sast.taint.summary.MethodSummary;
import com.oversecured.sast.taint.model.RuleFile;
import com.oversecured.sast.taint.rules.RuleLoader;
import com.oversecured.sast.taint.summary.SummaryComputer;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Public taint analyzer API. Loads the AST index, manifest facts, and a rule, runs the staged
 * engine (summaries, ICC, flow-sensitive intra-procedural propagation), and produces the shared
 * analyzer-agnostic {@code FindingsDoc}.
 */
public final class TaintAnalyzer {

    private static final Comparator<Finding> ORDER = Comparator
            .comparing(Finding::ruleId)
            .thenComparing(f -> f.flow().isEmpty() ? "" : f.flow().get(0).file())
            .thenComparingInt(f -> f.flow().isEmpty() ? 0 : f.flow().get(0).line())
            .thenComparing(Finding::message);

    /** Load artifacts from disk and analyze every rule in the rule file. */
    public FindingsDoc analyze(Path astIndexDir, Path factsJson, Path ruleYaml) {
        return analyze(AstIndex.load(astIndexDir), readFacts(factsJson), new RuleLoader().load(ruleYaml));
    }

    /** Analyze every rule in a loaded rule file against an already-loaded index + facts. */
    public FindingsDoc analyze(AstIndex index, ManifestFacts facts, RuleFile ruleFile) {
        List<Finding> findings = new ArrayList<>();
        for (Rule rule : ruleFile.getRules()) {
            findings.addAll(analyze(index, facts, rule).findings());
        }
        findings.sort(ORDER);
        return new FindingsDoc("taint-engine", findings);
    }

    private static ManifestFacts readFacts(Path factsJson) {
        try {
            return Json.read(Files.readAllBytes(factsJson), ManifestFacts.class);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read facts: " + factsJson, e);
        }
    }

    /** Analyze from disk and write the shared {@code FindingsDoc} JSON to {@code outJson}. */
    public void run(Path astIndexDir, Path factsJson, Path ruleYaml, Path outJson) {
        FindingsDoc doc = analyze(astIndexDir, factsJson, ruleYaml);
        writeDoc(doc, outJson);
    }

    /** One rule file to analyze and where to write its findings. */
    public record RuleRun(Path ruleYaml, Path outJson) {
    }

    /**
     * Analyze several rule files against a single load of the AST index + facts. The AST index load
     * re-parses the whole decompiled source tree (see {@link AstIndex#load}); running each rule as
     * its own activity re-parses N times and, under Temporal fan-out, N times in parallel — the
     * dominant cost and a memory blow-up. Loading once and looping the rules here is the parse-once
     * path: same per-rule output files, a fraction of the work and heap.
     */
    public void runBatch(Path astIndexDir, Path factsJson, List<RuleRun> runs) {
        AstIndex index = AstIndex.load(astIndexDir);
        ManifestFacts facts = readFacts(factsJson);
        for (RuleRun run : runs) {
            writeDoc(analyze(index, facts, new RuleLoader().load(run.ruleYaml())), run.outJson());
        }
    }

    private void writeDoc(FindingsDoc doc, Path outJson) {
        try {
            if (outJson.getParent() != null) {
                Files.createDirectories(outJson.getParent());
            }
            Files.write(outJson, Json.writeBytes(doc));
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to write findings: " + outJson, e);
        }
    }

    public FindingsDoc analyze(AstIndex index, ManifestFacts facts, Rule rule) {
        // Scope analysis to the app's own package (from manifest facts); bundled library code that a
        // decompiled apk inlines (androidx/kotlin/com.google/android.*) is skipped from the walk but
        // still backs type resolution. Blank package = analyze everything (source-tree fixtures).
        String appRoot = facts.packageName();

        RuleMatcher matcher = RuleMatcher.forRule(rule);
        List<MethodSummary> summaries = new SummaryComputer(index, matcher, rule, appRoot).compute();
        IccModel icc = IccModel.collect(index, matcher, rule, appRoot);
        IntraProceduralAnalyzer analyzer = new IntraProceduralAnalyzer(index, matcher, rule, summaries, icc);

        ReachabilityFilter reachability = new ReachabilityFilter(facts);
        List<CandidateFinding> candidates = new ArrayList<>();
        for (var cu : index.units(appRoot)) {
            for (MethodDeclaration method : cu.findAll(MethodDeclaration.class)) {
                for (CandidateFinding c : analyzer.analyzeMethod(method)) {
                    if (!reachability.keep(c, rule.getManifestConditions())) {
                        continue;
                    }
                    String reason = reachability.reason(c);
                    candidates.add(reason == null ? c : c.withNote(reason));
                }
            }
        }
        return new FindingsDoc("taint-engine", normalize(candidates, rule));
    }

    private List<Finding> normalize(List<CandidateFinding> candidates, Rule rule) {
        // Collapse candidates that share a rule and source origin (e.g. a constructor sink and the
        // later open() sink reached from the same tainted value) into one, keeping the longer flow
        // so the terminal sink step is preferred.
        java.util.Map<String, CandidateFinding> bySource = new java.util.LinkedHashMap<>();
        for (CandidateFinding c : candidates) {
            if (c.flow().isEmpty()) {
                continue;
            }
            String key = dedupKey(c);
            CandidateFinding existing = bySource.get(key);
            if (existing == null || c.flow().size() > existing.flow().size()) {
                bySource.put(key, c);
            }
        }
        List<Finding> findings = new ArrayList<>();
        for (CandidateFinding c : bySource.values()) {
            findings.add(toFinding(c, rule));
        }
        return findings;
    }

    private static String dedupKey(CandidateFinding c) {
        FlowStep source = c.flow().get(0);
        return c.ruleId() + "::" + source.file() + "::" + source.line();
    }

    private static Finding toFinding(CandidateFinding c, Rule rule) {
        return new Finding(
                rule.getId(),
                rule.getVulnerabilityClass(),
                rule.getSeverity(),
                rule.getMessage(),
                rule.getCwe(),
                rule.getOwaspMobile(),
                c.flow(),
                c.notes());
    }
}
