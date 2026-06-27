package com.oversecured.sast.taint.cfg;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Ordered CFG nodes plus the entry node id for one method. */
public final class ControlFlowGraph {
    private final List<CfgNode> nodes;
    private final int entryId;
    private final Map<Integer, CfgNode> byId;

    public ControlFlowGraph(List<CfgNode> nodes, int entryId) {
        this.nodes = List.copyOf(nodes);
        this.entryId = entryId;
        Map<Integer, CfgNode> map = new LinkedHashMap<>();
        for (CfgNode n : this.nodes) {
            map.put(n.id(), n);
        }
        this.byId = map;
    }

    public List<CfgNode> nodes() {
        return nodes;
    }

    public int entryId() {
        return entryId;
    }

    public CfgNode node(int id) {
        return byId.get(id);
    }

    public Optional<CfgNode> entry() {
        return Optional.ofNullable(byId.get(entryId));
    }
}
