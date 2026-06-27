package com.oversecured.sast.taint.flow;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.CastExpr;
import com.github.javaparser.ast.expr.EnclosedExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.FieldAccessExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.github.javaparser.ast.expr.VariableDeclarationExpr;
import com.github.javaparser.ast.stmt.BlockStmt;
import com.github.javaparser.ast.stmt.ExpressionStmt;
import com.github.javaparser.ast.stmt.ForEachStmt;
import com.github.javaparser.ast.stmt.ForStmt;
import com.github.javaparser.ast.stmt.IfStmt;
import com.github.javaparser.ast.stmt.ReturnStmt;
import com.github.javaparser.ast.stmt.Statement;
import com.github.javaparser.ast.stmt.SwitchStmt;
import com.github.javaparser.ast.stmt.TryStmt;
import com.github.javaparser.ast.stmt.WhileStmt;
import com.oversecured.sast.common.FlowStep;
import com.oversecured.sast.parser.AstIndex;
import com.oversecured.sast.taint.match.RuleMatcher;
import com.oversecured.sast.taint.model.Rule;
import com.oversecured.sast.taint.model.SinkSpec;
import com.oversecured.sast.taint.summary.MethodSummary;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Flow-sensitive intra-procedural taint propagation over one method.
 *
 * <p>Implemented as a recursive AST walk threading an immutable {@link TaintState}: sequential
 * statements give flow-sensitivity (reassignment to a clean value kills taint), and branches are
 * walked with per-branch state then merged. Sources/sinks/propagators are matched by resolved
 * signature via {@link RuleMatcher}; no vulnerability class is hardcoded.
 */
public final class IntraProceduralAnalyzer {

    private final AstIndex index;
    private final RuleMatcher matcher;
    private final Rule rule;
    private final List<MethodSummary> summaries;
    private final java.util.Map<String, MethodSummary> summaryBySignature;

    private List<CandidateFinding> findings;
    private String currentComponent;
    private boolean sawTaintedReturn;

    public IntraProceduralAnalyzer(AstIndex index, RuleMatcher matcher, Rule rule,
                                   List<MethodSummary> summaries) {
        this.index = index;
        this.matcher = matcher;
        this.rule = rule;
        this.summaries = List.copyOf(summaries);
        java.util.Map<String, MethodSummary> map = new java.util.HashMap<>();
        for (MethodSummary s : this.summaries) {
            map.put(s.canonicalMethodSignature(), s);
        }
        this.summaryBySignature = map;
    }

    /**
     * Summary-computation probe: returns whether tainting {@code paramIndex} alone makes any
     * return expression of {@code method} tainted, under the currently-known summaries.
     */
    public boolean returnsTaintedForParam(MethodDeclaration method, int paramIndex) {
        this.findings = new ArrayList<>();
        this.currentComponent = null;
        this.sawTaintedReturn = false;
        String paramName = method.getParameter(paramIndex).getNameAsString();
        TaintState seed = TaintState.empty().taint(AccessPath.of(paramName), new FlowTrace());
        method.getBody().ifPresent(body -> exec(body, seed));
        return sawTaintedReturn;
    }

    public List<CandidateFinding> analyzeMethod(MethodDeclaration method) {
        this.findings = new ArrayList<>();
        this.currentComponent = method.findAncestor(TypeDeclaration.class)
                .flatMap(t -> ((TypeDeclaration<?>) t).getFullyQualifiedName())
                .orElse(null);
        method.getBody().ifPresent(body -> exec(body, TaintState.empty()));
        return findings;
    }

    // ---- statement execution -------------------------------------------------

    private TaintState exec(Statement stmt, TaintState state) {
        if (stmt instanceof BlockStmt block) {
            TaintState cur = state;
            for (Statement s : block.getStatements()) {
                cur = exec(s, cur);
            }
            return cur;
        }
        if (stmt instanceof ExpressionStmt es) {
            return handleExpression(es.getExpression(), state);
        }
        if (stmt instanceof IfStmt ifStmt) {
            eval(ifStmt.getCondition(), state); // side effects (nested sinks/sources)
            TaintState thenState = exec(ifStmt.getThenStmt(), thenBranchState(ifStmt, state));
            TaintState elseState = ifStmt.getElseStmt().map(s -> exec(s, state)).orElse(state);
            return thenState.merge(elseState);
        }
        if (stmt instanceof WhileStmt ws) {
            return loop(ws.getBody(), state);
        }
        if (stmt instanceof ForStmt fs) {
            return loop(fs.getBody(), state);
        }
        if (stmt instanceof ForEachStmt fe) {
            return loop(fe.getBody(), state);
        }
        if (stmt instanceof TryStmt ts) {
            TaintState cur = exec(ts.getTryBlock(), state);
            for (var c : ts.getCatchClauses()) {
                cur = cur.merge(exec(c.getBody(), state));
            }
            if (ts.getFinallyBlock().isPresent()) {
                cur = exec(ts.getFinallyBlock().get(), cur);
            }
            return cur;
        }
        if (stmt instanceof SwitchStmt sw) {
            eval(sw.getSelector(), state);
            TaintState result = state;
            for (var entry : sw.getEntries()) {
                TaintState branch = state;
                for (Statement s : entry.getStatements()) {
                    branch = exec(s, branch);
                }
                result = result.merge(branch);
            }
            return result;
        }
        if (stmt instanceof ReturnStmt rs) {
            rs.getExpression().ifPresent(e -> {
                if (eval(e, state).isPresent()) {
                    sawTaintedReturn = true;
                }
            });
            return state;
        }
        // unsupported statement: walk nested expressions for side effects only
        stmt.findAll(Expression.class).forEach(e -> { });
        return state;
    }

    private static final java.util.Set<String> INCOMPLETE_SANITIZER_NAMES =
            java.util.Set.of("endsWith", "contains", "startsWith");

    /**
     * Apply guard semantics to the then-branch state. A matched rule sanitizer call in the condition
     * kills taint on its operands. A bypassable {@code endsWith/contains/startsWith} host check is an
     * <em>incomplete</em> sanitizer: taint survives but the carrying trace is annotated.
     */
    private TaintState thenBranchState(IfStmt ifStmt, TaintState state) {
        TaintState cur = state;
        for (MethodCallExpr mce : ifStmt.getCondition().findAll(MethodCallExpr.class)) {
            Optional<String> sig = index.resolveSignature(mce);
            if (sig.isPresent() && matcher.sanitizerFor(sig.get()).isPresent()) {
                cur = killSanitizedOperands(mce, cur);
            } else if (isIncompleteSanitizer(mce, cur)) {
                cur = annotateIncomplete(mce, cur);
            }
        }
        return cur;
    }

    private TaintState killSanitizedOperands(MethodCallExpr mce, TaintState state) {
        TaintState cur = state;
        if (mce.getScope().isPresent()) {
            cur = killIfTainted(mce.getScope().get(), cur);
        }
        for (Expression arg : mce.getArguments()) {
            cur = killIfTainted(arg, cur);
        }
        return cur;
    }

    private static TaintState killIfTainted(Expression e, TaintState state) {
        AccessPath p = targetPath(e);
        return (p != null && state.isTainted(p)) ? state.kill(p) : state;
    }

    private boolean isIncompleteSanitizer(MethodCallExpr mce, TaintState state) {
        if (!INCOMPLETE_SANITIZER_NAMES.contains(mce.getNameAsString())) {
            return false;
        }
        Optional<Expression> scope = mce.getScope();
        if (scope.isEmpty()) {
            return false;
        }
        AccessPath p = targetPath(scope.get());
        if (p == null || !state.isTainted(p)) {
            return false;
        }
        return mce.getArguments().stream()
                .anyMatch(a -> a instanceof StringLiteralExpr sl && sl.getValue().contains("."));
    }

    private TaintState annotateIncomplete(MethodCallExpr mce, TaintState state) {
        AccessPath p = targetPath(mce.getScope().orElseThrow());
        FlowTrace annotated = state.trace(p).addNote("incomplete-sanitizer: " + mce + " is bypassable");
        return state.taint(p, annotated);
    }

    private TaintState loop(Statement body, TaintState state) {
        TaintState cur = state;
        // Two passes approximate a fixpoint; taint generation is monotonic.
        for (int i = 0; i < 2; i++) {
            cur = cur.merge(exec(body, cur));
        }
        return cur;
    }

    private TaintState handleExpression(Expression expr, TaintState state) {
        if (expr instanceof VariableDeclarationExpr vde) {
            TaintState cur = state;
            for (VariableDeclarator decl : vde.getVariables()) {
                AccessPath path = AccessPath.of(decl.getNameAsString());
                TaintState snapshot = cur;
                Optional<FlowTrace> t = decl.getInitializer().flatMap(init -> eval(init, snapshot));
                cur = t.isPresent() ? cur.taint(path, t.get()) : cur.kill(path);
            }
            return cur;
        }
        if (expr instanceof AssignExpr ae) {
            Optional<FlowTrace> t = eval(ae.getValue(), state);
            AccessPath path = targetPath(ae.getTarget());
            if (path == null) {
                return state;
            }
            return t.isPresent() ? state.taint(path, t.get()) : state.kill(path);
        }
        eval(expr, state); // standalone call etc. — side effects (sinks)
        return state;
    }

    // ---- expression taint evaluation ----------------------------------------

    /** Returns the flow trace tainting {@code expr}, or empty if untainted. Emits sink findings. */
    private Optional<FlowTrace> eval(Expression expr, TaintState state) {
        if (expr instanceof NameExpr ne) {
            AccessPath p = AccessPath.of(ne.getNameAsString());
            return state.isTainted(p) ? Optional.of(state.trace(p)) : Optional.empty();
        }
        if (expr instanceof FieldAccessExpr fa) {
            AccessPath p = fieldPath(fa);
            return p != null && state.isTainted(p) ? Optional.of(state.trace(p)) : Optional.empty();
        }
        if (expr instanceof EnclosedExpr en) {
            return eval(en.getInner(), state);
        }
        if (expr instanceof CastExpr ce) {
            return eval(ce.getExpression(), state);
        }
        if (expr instanceof BinaryExpr be) {
            Optional<FlowTrace> l = eval(be.getLeft(), state);
            Optional<FlowTrace> r = eval(be.getRight(), state);
            return shorter(l, r);
        }
        if (expr instanceof MethodCallExpr mce) {
            return evalCall(mce, state);
        }
        return Optional.empty();
    }

    private Optional<FlowTrace> evalCall(MethodCallExpr mce, TaintState state) {
        Optional<FlowTrace> scopeTrace = mce.getScope().flatMap(s -> eval(s, state));
        List<Optional<FlowTrace>> argTraces = new ArrayList<>();
        for (Expression arg : mce.getArguments()) {
            argTraces.add(eval(arg, state));
        }

        Optional<String> sig = index.resolveSignature(mce);
        if (sig.isEmpty()) {
            return Optional.empty();
        }
        String resolved = sig.get();

        Optional<SinkSpec> sink = matcher.sinkFor(resolved);
        if (sink.isPresent()) {
            for (int idx : sink.get().getTaintedArgs()) {
                if (idx >= 0 && idx < argTraces.size() && argTraces.get(idx).isPresent()) {
                    emitFinding(argTraces.get(idx).get(), mce);
                    break;
                }
            }
        }
        if (matcher.sourceFor(resolved).isPresent()) {
            return Optional.of(new FlowTrace().addStep(step(mce, "source: " + mce)));
        }
        if (matcher.isPropagator(resolved)) {
            List<Optional<FlowTrace>> inputs = new ArrayList<>(argTraces);
            inputs.add(scopeTrace);
            Optional<FlowTrace> in = inputs.stream()
                    .filter(Optional::isPresent).map(Optional::get)
                    .min((a, b) -> Integer.compare(a.length(), b.length()));
            if (in.isPresent()) {
                return Optional.of(in.get().addStep(step(mce, "propagator: " + mce)));
            }
        }
        return applySummary(mce, resolved, scopeTrace, argTraces);
    }

    /** Apply a method summary: if a parameter that taints the return is tainted, taint the result. */
    private Optional<FlowTrace> applySummary(MethodCallExpr mce, String resolvedSignature,
                                             Optional<FlowTrace> scopeTrace,
                                             List<Optional<FlowTrace>> argTraces) {
        MethodSummary summary = summaryBySignature.get(resolvedSignature);
        if (summary == null) {
            return Optional.empty();
        }
        for (int i : summary.returnTaintedIfParamsTainted()) {
            if (i >= 0 && i < argTraces.size() && argTraces.get(i).isPresent()) {
                return Optional.of(argTraces.get(i).get().addStep(step(mce, "via summary: " + mce)));
            }
        }
        return Optional.empty();
    }

    protected void emitFinding(FlowTrace argTrace, Node sink) {
        FlowTrace full = argTrace.addStep(step(sink, "sink: " + sink));
        findings.add(new CandidateFinding(rule.getId(), currentComponent, full.steps(), full.notes()));
    }

    // ---- helpers -------------------------------------------------------------

    protected RuleMatcher matcher() {
        return matcher;
    }

    protected AstIndex index() {
        return index;
    }

    protected List<MethodSummary> summaries() {
        return summaries;
    }

    private static FlowStep step(Node node, String label) {
        return new FlowStep(fileName(node), line(node), label);
    }

    private static String fileName(Node node) {
        return node.findCompilationUnit()
                .flatMap(cu -> cu.getStorage())
                .map(s -> s.getFileName())
                .orElse("unknown");
    }

    private static int line(Node node) {
        return node.getBegin().map(p -> p.line).orElse(0);
    }

    private static AccessPath targetPath(Expression target) {
        if (target instanceof NameExpr ne) {
            return AccessPath.of(ne.getNameAsString());
        }
        if (target instanceof FieldAccessExpr fa) {
            return fieldPath(fa);
        }
        return null;
    }

    private static AccessPath fieldPath(FieldAccessExpr fa) {
        if (fa.getScope() instanceof NameExpr base) {
            return AccessPath.field(base.getNameAsString(), fa.getNameAsString());
        }
        return AccessPath.of(fa.toString());
    }

    private static Optional<FlowTrace> shorter(Optional<FlowTrace> a, Optional<FlowTrace> b) {
        if (a.isPresent() && b.isPresent()) {
            return a.get().length() <= b.get().length() ? a : b;
        }
        return a.isPresent() ? a : b;
    }
}
