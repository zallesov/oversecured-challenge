package com.oversecured.sast.taint.summary;

import java.util.Set;

/**
 * A bounded inter-procedural summary for one project method:
 * which parameters, when tainted, taint the return value or the receiver's fields, and which
 * parameters, when tainted, reach a sink inside the method's body.
 */
public final class MethodSummary {
    private final String canonicalMethodSignature;
    private final Set<Integer> returnTaintedIfParamsTainted;
    private final Set<Integer> taintsReceiverFieldsIfParamsTainted;
    private final Set<Integer> sinkReachingParams;

    public MethodSummary(String canonicalMethodSignature,
                         Set<Integer> returnTaintedIfParamsTainted,
                         Set<Integer> taintsReceiverFieldsIfParamsTainted,
                         Set<Integer> sinkReachingParams) {
        this.canonicalMethodSignature = canonicalMethodSignature;
        this.returnTaintedIfParamsTainted = Set.copyOf(returnTaintedIfParamsTainted);
        this.taintsReceiverFieldsIfParamsTainted = Set.copyOf(taintsReceiverFieldsIfParamsTainted);
        this.sinkReachingParams = Set.copyOf(sinkReachingParams);
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

    /** Parameters that, when tainted, cause a sink to fire inside the method body. */
    public Set<Integer> sinkReachingParams() {
        return sinkReachingParams;
    }
}
