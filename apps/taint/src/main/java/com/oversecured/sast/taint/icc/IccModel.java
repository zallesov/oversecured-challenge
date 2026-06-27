package com.oversecured.sast.taint.icc;

import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.CastExpr;
import com.github.javaparser.ast.expr.ClassExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.github.javaparser.ast.expr.VariableDeclarationExpr;
import com.oversecured.sast.common.FlowStep;
import com.oversecured.sast.parser.AstIndex;
import com.oversecured.sast.taint.match.RuleMatcher;
import com.oversecured.sast.taint.model.Rule;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Light inter-component-communication model. Scans every method for the Android pattern
 * {@code new Intent(ctx, Target.class); intent.putExtra(key, tainted); startActivity(intent);} and
 * records the resulting {@link IntentExtraFlow}s, so the taint engine can treat the target
 * component's {@code getStringExtra(key)} as a synthetic cross-component source.
 *
 * <p>Scope: string-literal keys and explicit {@code new Intent(ctx, Target.class)} targets only.
 * Taint of the {@code putExtra} value is detected flow-insensitively (a variable assigned from a
 * matched rule source), which is sufficient for the supported pattern.
 */
public final class IccModel {

    private static final Set<String> START_CALLS = Set.of("startActivity", "startService");

    private final List<IntentExtraFlow> flows;

    private IccModel(List<IntentExtraFlow> flows) {
        this.flows = List.copyOf(flows);
    }

    public List<IntentExtraFlow> flows() {
        return flows;
    }

    /** An active ICC flow delivering {@code key} into {@code component}, if any. */
    public Optional<IntentExtraFlow> activeSource(String component, String key) {
        return flows.stream()
                .filter(f -> f.targetComponent().equals(component) && f.key().equals(key))
                .findFirst();
    }

    public static IccModel collect(AstIndex index, RuleMatcher matcher, Rule rule, String appRoot) {
        List<IntentExtraFlow> flows = new ArrayList<>();
        for (var cu : index.units(appRoot)) {
            for (MethodDeclaration method : cu.findAll(MethodDeclaration.class)) {
                collectFromMethod(index, matcher, method, flows);
            }
        }
        return new IccModel(flows);
    }

    private static void collectFromMethod(AstIndex index, RuleMatcher matcher,
                                          MethodDeclaration method, List<IntentExtraFlow> out) {
        if (method.getBody().isEmpty()) {
            return;
        }
        String component = method.findAncestor(TypeDeclaration.class)
                .flatMap(t -> ((TypeDeclaration<?>) t).getFullyQualifiedName())
                .orElse(null);
        if (component == null) {
            return;
        }

        Set<String> taintedVars = new HashSet<>();
        Map<String, String> intentTargets = new HashMap<>();
        // pending putExtra edges keyed by intent variable name
        Map<String, List<Pending>> pending = new HashMap<>();

        // Scan the whole method (incl. nested branches/loops), not just top-level statements:
        // real ICC (e.g. OVAA's DeeplinkActivity) builds and dispatches the intent inside if-blocks.
        // Phase 1: tainted variables and intent targets from assignments anywhere in the method.
        for (VariableDeclarationExpr vde : method.findAll(VariableDeclarationExpr.class)) {
            vde.getVariables().forEach(d -> d.getInitializer().ifPresent(init ->
                    classify(index, matcher, d.getNameAsString(), init, taintedVars, intentTargets)));
        }
        for (AssignExpr ae : method.findAll(AssignExpr.class)) {
            if (ae.getTarget() instanceof NameExpr target) {
                classify(index, matcher, target.getNameAsString(), ae.getValue(), taintedVars, intentTargets);
            }
        }
        // Phase 2: pending tainted putExtra edges. Phase 3: activate them on startActivity/startService.
        for (MethodCallExpr mce : method.findAll(MethodCallExpr.class)) {
            recordPutExtra(mce, taintedVars, pending);
        }
        for (MethodCallExpr mce : method.findAll(MethodCallExpr.class)) {
            recordStart(index, mce, component, intentTargets, pending, out);
        }
    }

    private static void classify(AstIndex index, RuleMatcher matcher, String name, Expression rhs,
                                 Set<String> taintedVars, Map<String, String> intentTargets) {
        if (rhs instanceof MethodCallExpr mce
                && index.resolveSignature(mce).flatMap(matcher::sourceFor).isPresent()) {
            taintedVars.add(name);
        } else if (rhs instanceof ObjectCreationExpr oce && isIntentCreation(oce)) {
            targetOf(oce).ifPresent(t -> intentTargets.put(name, t));
        }
    }

    private static void recordPutExtra(Expression expr, Set<String> taintedVars,
                                       Map<String, List<Pending>> pending) {
        if (!(expr instanceof MethodCallExpr mce) || !mce.getNameAsString().equals("putExtra")) {
            return;
        }
        if (mce.getScope().isEmpty() || !(mce.getScope().get() instanceof NameExpr intentVar)) {
            return;
        }
        if (mce.getArguments().size() < 2
                || !(mce.getArgument(0) instanceof StringLiteralExpr keyLit)
                || !(mce.getArgument(1) instanceof NameExpr valueVar)) {
            return;
        }
        if (!taintedVars.contains(valueVar.getNameAsString())) {
            return;
        }
        FlowStep step = new FlowStep(fileName(mce), line(mce),
                "putExtra(\"" + keyLit.getValue() + "\") + startActivity");
        pending.computeIfAbsent(intentVar.getNameAsString(), k -> new ArrayList<>())
                .add(new Pending(keyLit.getValue(), step));
    }

    private static void recordStart(AstIndex index, Expression expr, String component,
                                    Map<String, String> intentTargets,
                                    Map<String, List<Pending>> pending, List<IntentExtraFlow> out) {
        if (!(expr instanceof MethodCallExpr mce) || !START_CALLS.contains(mce.getNameAsString())) {
            return;
        }
        if (mce.getArguments().isEmpty() || !(mce.getArgument(0) instanceof NameExpr intentVar)) {
            return;
        }
        String var = intentVar.getNameAsString();
        String target = intentTargets.get(var);
        if (target == null) {
            return;
        }
        for (Pending p : pending.getOrDefault(var, List.of())) {
            out.add(new IntentExtraFlow(p.key, component, target, p.step));
        }
    }

    private static boolean isIntentCreation(ObjectCreationExpr oce) {
        return oce.getType().getNameAsString().equals("Intent") && oce.getArguments().size() >= 2;
    }

    /** Peel any number of nested cast expressions, e.g. jadx's {@code (Class<?>) X.class}. */
    private static Expression unwrapCasts(Expression expr) {
        Expression e = expr;
        while (e instanceof CastExpr cast) {
            e = cast.getExpression();
        }
        return e;
    }

    private static Optional<String> targetOf(ObjectCreationExpr oce) {
        // jadx decompiles `new Intent(this, X.class)` as `new Intent(this, (Class<?>) X.class)` — the
        // class arg is wrapped in an explicit cast that hand-written source omits. Unwrap casts so
        // the ICC target resolves on decompiled apk input, not only on raw source.
        Expression arg = unwrapCasts(oce.getArgument(1));
        if (!(arg instanceof ClassExpr ce)) {
            return Optional.empty();
        }
        try {
            return Optional.of(ce.getType().resolve().describe());
        } catch (RuntimeException | StackOverflowError e) {
            // Fail-soft: fall back to the textual type name when the symbol solver cannot resolve
            // (or infinite-loops on recursive generic bounds, androidx + android.jar).
            return Optional.of(ce.getType().toString());
        }
    }

    private static String fileName(com.github.javaparser.ast.Node node) {
        return node.findCompilationUnit()
                .flatMap(cu -> cu.getStorage())
                .map(s -> s.getFileName())
                .orElse("unknown");
    }

    private static int line(com.github.javaparser.ast.Node node) {
        return node.getBegin().map(p -> p.line).orElse(0);
    }

    private record Pending(String key, FlowStep step) {
    }
}
