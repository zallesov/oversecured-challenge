package com.oversecured.sast.taint;

import com.github.javaparser.ast.body.MethodDeclaration;
import com.oversecured.sast.common.Finding;
import com.oversecured.sast.common.FindingsDoc;
import com.oversecured.sast.common.FlowStep;
import com.oversecured.sast.common.ManifestFacts;
import com.oversecured.sast.taint.flow.CandidateFinding;
import com.oversecured.sast.taint.flow.IntraProceduralAnalyzer;
import com.oversecured.sast.taint.icc.IccModel;
import com.oversecured.sast.taint.match.RuleMatcher;
import com.oversecured.sast.taint.model.Rule;
import com.oversecured.sast.taint.summary.MethodSummary;
import com.oversecured.sast.taint.summary.SummaryComputer;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Public taint analyzer API. Loads the AST index, manifest facts, and a rule, runs the staged
 * engine (summaries, ICC, flow-sensitive intra-procedural propagation), and produces the shared
 * analyzer-agnostic {@code FindingsDoc}.
 */
public final class TaintAnalyzer {

    public FindingsDoc analyze(com.oversecured.sast.parser.AstIndex index, ManifestFacts facts, Rule rule) {
        RuleMatcher matcher = RuleMatcher.forRule(rule);
        List<MethodSummary> summaries = new SummaryComputer(index, matcher, rule).compute();
        IccModel icc = IccModel.collect(index, matcher, rule);
        IntraProceduralAnalyzer analyzer = new IntraProceduralAnalyzer(index, matcher, rule, summaries, icc);

        List<CandidateFinding> candidates = new ArrayList<>();
        for (var cu : index.units()) {
            for (MethodDeclaration method : cu.findAll(MethodDeclaration.class)) {
                candidates.addAll(analyzer.analyzeMethod(method));
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
