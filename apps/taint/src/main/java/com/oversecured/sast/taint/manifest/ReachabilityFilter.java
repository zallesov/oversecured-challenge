package com.oversecured.sast.taint.manifest;

import com.oversecured.sast.common.ComponentFact;
import com.oversecured.sast.common.FlowStep;
import com.oversecured.sast.common.ManifestFacts;
import com.oversecured.sast.taint.flow.CandidateFinding;
import com.oversecured.sast.taint.model.ManifestConditions;

/**
 * Suppresses findings whose source component is neither exported nor reachable from an exported
 * component via ICC, when the rule requires exported reachability. This serves the challenge's
 * false-positive-rate-to-zero goal (spec §6.7).
 */
public final class ReachabilityFilter {

    private final ManifestFacts facts;

    public ReachabilityFilter(ManifestFacts facts) {
        this.facts = facts;
    }

    /** Whether to retain {@code candidate} under the rule's {@code conditions}. */
    public boolean keep(CandidateFinding candidate, ManifestConditions conditions) {
        if (conditions == null || !conditions.isReachableFromExported()) {
            return true;
        }
        return isExported(candidate.sourceComponent()) || hasIccStep(candidate);
    }

    /** Human-readable reachability reason for a kept finding, for annotation. */
    public String reason(CandidateFinding candidate) {
        if (isExported(candidate.sourceComponent())) {
            return "entry component exported: " + candidate.sourceComponent();
        }
        if (hasIccStep(candidate)) {
            return "reachable from exported component via ICC: " + candidate.sourceComponent();
        }
        return null;
    }

    private boolean isExported(String component) {
        if (component == null) {
            return false;
        }
        return facts.components().stream()
                .filter(c -> c.name().equals(component))
                .anyMatch(ComponentFact::exported);
    }

    private static boolean hasIccStep(CandidateFinding candidate) {
        for (FlowStep step : candidate.flow()) {
            String label = step.label();
            if (label.contains("startActivity") || label.contains("startService")
                    || label.contains("putExtra")) {
                return true;
            }
        }
        return false;
    }
}
