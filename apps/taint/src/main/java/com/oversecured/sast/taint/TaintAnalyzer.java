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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

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
        AstIndex index = AstIndex.load(astIndexDir);
        ManifestFacts facts;
        try {
            facts = Json.read(Files.readAllBytes(factsJson), ManifestFacts.class);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read facts: " + factsJson, e);
        }
        RuleFile ruleFile = new RuleLoader().load(ruleYaml);

        List<Finding> findings = new ArrayList<>();
        for (Rule rule : ruleFile.getRules()) {
            findings.addAll(analyze(index, facts, rule).findings());
        }
        findings.sort(ORDER);
        return new FindingsDoc("taint-engine", findings);
    }

    /** Analyze from disk and write the shared {@code FindingsDoc} JSON to {@code outJson}. */
    public void run(Path astIndexDir, Path factsJson, Path ruleYaml, Path outJson) {
        FindingsDoc doc = analyze(astIndexDir, factsJson, ruleYaml);
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
        RuleMatcher matcher = RuleMatcher.forRule(rule);
        List<MethodSummary> summaries = new SummaryComputer(index, matcher, rule).compute();
        IccModel icc = IccModel.collect(index, matcher, rule);
        IntraProceduralAnalyzer analyzer = new IntraProceduralAnalyzer(index, matcher, rule, summaries, icc);

        ReachabilityFilter reachability = new ReachabilityFilter(facts);
        List<CandidateFinding> candidates = new ArrayList<>();
        for (var cu : index.units()) {
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
        Set<String> seen = new LinkedHashSet<>();
        List<Finding> findings = new ArrayList<>();
        for (CandidateFinding c : candidates) {
            if (seen.add(dedupKey(c))) {
                findings.add(toFinding(c, rule));
            }
        }
        return findings;
    }

    private static String dedupKey(CandidateFinding c) {
        FlowStep sink = c.flow().get(c.flow().size() - 1);
        StringBuilder labels = new StringBuilder();
        for (FlowStep s : c.flow()) {
            labels.append(s.label()).append('|');
        }
        return c.ruleId() + "::" + sink.file() + "::" + sink.line() + "::" + labels;
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
