package com.oversecured.sast.taint.match;

import com.oversecured.sast.taint.model.Rule;
import com.oversecured.sast.taint.model.SanitizerSpec;
import com.oversecured.sast.taint.model.SinkSpec;
import com.oversecured.sast.taint.model.SourceSpec;
import com.oversecured.sast.taint.rules.RuleSignatures;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Matches resolved call signatures against one rule's sources, sinks, sanitizers,
 * and propagators. Matching is by exact canonical signature string (not method name),
 * so the matcher never hardcodes any vulnerability class.
 */
public final class RuleMatcher {

    private final Map<String, SourceSpec> sources;
    private final Map<String, SinkSpec> sinks;
    private final Map<String, SanitizerSpec> sanitizers;
    private final Set<String> propagators;

    private RuleMatcher(
            Map<String, SourceSpec> sources,
            Map<String, SinkSpec> sinks,
            Map<String, SanitizerSpec> sanitizers,
            Set<String> propagators) {
        this.sources = sources;
        this.sinks = sinks;
        this.sanitizers = sanitizers;
        this.propagators = propagators;
    }

    public static RuleMatcher forRule(Rule rule) {
        Map<String, SourceSpec> sources = new HashMap<>();
        for (SourceSpec s : rule.getSources()) {
            sources.put(RuleSignatures.canonical(s.getSignature()), s);
        }
        Map<String, SinkSpec> sinks = new HashMap<>();
        for (SinkSpec s : rule.getSinks()) {
            sinks.put(RuleSignatures.canonical(s.getSignature()), s);
        }
        Map<String, SanitizerSpec> sanitizers = new HashMap<>();
        for (SanitizerSpec s : rule.getSanitizers()) {
            sanitizers.put(RuleSignatures.canonical(s.getSignature()), s);
        }
        Set<String> propagators = new java.util.HashSet<>();
        for (String p : rule.getPropagators()) {
            propagators.add(RuleSignatures.canonical(p));
        }
        return new RuleMatcher(sources, sinks, sanitizers, propagators);
    }

    public Optional<SourceSpec> sourceFor(String resolvedSignature) {
        return Optional.ofNullable(sources.get(resolvedSignature));
    }

    public Optional<SinkSpec> sinkFor(String resolvedSignature) {
        return Optional.ofNullable(sinks.get(resolvedSignature));
    }

    public Optional<SanitizerSpec> sanitizerFor(String resolvedSignature) {
        return Optional.ofNullable(sanitizers.get(resolvedSignature));
    }

    public boolean isPropagator(String resolvedSignature) {
        return propagators.contains(resolvedSignature);
    }
}
