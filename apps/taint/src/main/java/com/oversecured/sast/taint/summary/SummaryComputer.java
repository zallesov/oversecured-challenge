package com.oversecured.sast.taint.summary;

import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.resolution.declarations.ResolvedMethodDeclaration;
import com.oversecured.sast.parser.AstIndex;
import com.oversecured.sast.taint.flow.IntraProceduralAnalyzer;
import com.oversecured.sast.taint.match.RuleMatcher;
import com.oversecured.sast.taint.model.Rule;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Computes bounded method summaries for project methods: which parameters, when tainted, taint
 * the method's return value. Iterates to a small fixpoint so helper-of-helper chains converge;
 * recursion that does not converge within the cap simply yields no extra summary.
 */
public final class SummaryComputer {

    private static final int MAX_PASSES = 5;

    private final AstIndex index;
    private final RuleMatcher matcher;
    private final Rule rule;
    private final String appRoot;

    public SummaryComputer(AstIndex index, RuleMatcher matcher, Rule rule, String appRoot) {
        this.index = index;
        this.matcher = matcher;
        this.rule = rule;
        this.appRoot = appRoot;
    }

    public List<MethodSummary> compute() {
        List<MethodDeclaration> methods = index.units(appRoot).stream()
                .flatMap(cu -> cu.findAll(MethodDeclaration.class).stream())
                .toList();

        Map<String, MethodSummary> current = new HashMap<>();
        for (int pass = 0; pass < MAX_PASSES; pass++) {
            Map<String, MethodSummary> next = new HashMap<>();
            List<MethodSummary> known = List.copyOf(current.values());
            for (MethodDeclaration method : methods) {
                String sig = canonicalSignature(method);
                if (sig == null) {
                    continue;
                }
                Set<Integer> returnTainted = computeReturnTaint(method, known);
                Set<Integer> sinkReaching = computeSinkReaching(method, known);
                next.put(sig, new MethodSummary(sig, returnTainted, Set.of(), sinkReaching));
            }
            boolean changed = !sameSummaries(current, next);
            current = next;
            if (!changed) {
                break;
            }
        }
        return List.copyOf(current.values());
    }

    private Set<Integer> computeReturnTaint(MethodDeclaration method, List<MethodSummary> known) {
        Set<Integer> tainting = new LinkedHashSet<>();
        IntraProceduralAnalyzer analyzer = new IntraProceduralAnalyzer(index, matcher, rule, known);
        for (int i = 0; i < method.getParameters().size(); i++) {
            if (analyzer.returnsTaintedForParam(method, i)) {
                tainting.add(i);
            }
        }
        return tainting;
    }

    private Set<Integer> computeSinkReaching(MethodDeclaration method, List<MethodSummary> known) {
        Set<Integer> reaching = new LinkedHashSet<>();
        IntraProceduralAnalyzer analyzer = new IntraProceduralAnalyzer(index, matcher, rule, known);
        for (int i = 0; i < method.getParameters().size(); i++) {
            if (analyzer.reachesSinkForParam(method, i)) {
                reaching.add(i);
            }
        }
        return reaching;
    }

    private static boolean sameSummaries(Map<String, MethodSummary> a, Map<String, MethodSummary> b) {
        if (!a.keySet().equals(b.keySet())) {
            return false;
        }
        for (String key : a.keySet()) {
            MethodSummary x = a.get(key);
            MethodSummary y = b.get(key);
            if (!x.returnTaintedIfParamsTainted().equals(y.returnTaintedIfParamsTainted())
                    || !x.sinkReachingParams().equals(y.sinkReachingParams())) {
                return false;
            }
        }
        return true;
    }

    private static String canonicalSignature(MethodDeclaration method) {
        try {
            ResolvedMethodDeclaration decl = method.resolve();
            StringBuilder params = new StringBuilder();
            for (int i = 0; i < decl.getNumberOfParams(); i++) {
                if (i > 0) {
                    params.append(',');
                }
                params.append(decl.getParam(i).getType().describe());
            }
            return "<" + decl.declaringType().getQualifiedName()
                    + ": " + decl.getReturnType().describe()
                    + " " + decl.getName()
                    + "(" + params + ")>";
        } catch (RuntimeException | StackOverflowError e) {
            // Unresolved project method: no summary. StackOverflowError guarded because the symbol
            // solver can infinite-loop on recursive generic bounds (androidx + android.jar); that
            // method just gets no summary instead of aborting the whole analysis (fail-soft).
            return null;
        }
    }
}
