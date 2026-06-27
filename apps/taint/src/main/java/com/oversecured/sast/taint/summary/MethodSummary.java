package com.oversecured.sast.taint.summary;

import java.util.Set;

/**
 * A bounded inter-procedural summary for one project method:
 * which parameters, when tainted, taint the return value or the receiver's fields.
 */
public final class MethodSummary {
    private final String canonicalMethodSignature;
    private final Set<Integer> returnTaintedIfParamsTainted;
    private final Set<Integer> taintsReceiverFieldsIfParamsTainted;

    public MethodSummary(String canonicalMethodSignature,
                         Set<Integer> returnTaintedIfParamsTainted,
                         Set<Integer> taintsReceiverFieldsIfParamsTainted) {
        this.canonicalMethodSignature = canonicalMethodSignature;
        this.returnTaintedIfParamsTainted = Set.copyOf(returnTaintedIfParamsTainted);
        this.taintsReceiverFieldsIfParamsTainted = Set.copyOf(taintsReceiverFieldsIfParamsTainted);
    }

    public String canonicalMethodSignature() {
        return canonicalMethodSignature;
    }

    public Set<Integer> returnTaintedIfParamsTainted() {
        return returnTaintedIfParamsTainted;
    }

    public Set<Integer> taintsReceiverFieldsIfParamsTainted() {
        return taintsReceiverFieldsIfParamsTainted;
    }
}
