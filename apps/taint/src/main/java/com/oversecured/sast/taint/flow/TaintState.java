package com.oversecured.sast.taint.flow;

import java.util.HashMap;
import java.util.Map;

/** Copy-on-write set of tainted access paths, each carrying its shortest known flow trace. */
public final class TaintState {
    private final Map<AccessPath, FlowTrace> tainted;

    private TaintState(Map<AccessPath, FlowTrace> tainted) {
        this.tainted = tainted;
    }

    public static TaintState empty() {
        return new TaintState(Map.of());
    }

    public boolean isTainted(AccessPath path) {
        return tainted.containsKey(path);
    }

    public FlowTrace trace(AccessPath path) {
        return tainted.get(path);
    }

    public TaintState taint(AccessPath path, FlowTrace trace) {
        Map<AccessPath, FlowTrace> next = new HashMap<>(tainted);
        next.put(path, trace);
        return new TaintState(next);
    }

    public TaintState kill(AccessPath path) {
        if (!tainted.containsKey(path)) {
            return this;
        }
        Map<AccessPath, FlowTrace> next = new HashMap<>(tainted);
        next.remove(path);
        return new TaintState(next);
    }

    /** Union of tainted paths; on conflict keep the shorter trace. */
    public TaintState merge(TaintState other) {
        Map<AccessPath, FlowTrace> next = new HashMap<>(tainted);
        for (Map.Entry<AccessPath, FlowTrace> e : other.tainted.entrySet()) {
            FlowTrace existing = next.get(e.getKey());
            if (existing == null || e.getValue().length() < existing.length()) {
                next.put(e.getKey(), e.getValue());
            }
        }
        return new TaintState(next);
    }
}
