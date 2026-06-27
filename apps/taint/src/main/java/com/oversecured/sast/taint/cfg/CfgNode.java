package com.oversecured.sast.taint.cfg;

import com.github.javaparser.ast.Node;
import java.util.List;

/** A statement-level CFG node: stable id, the AST node, and successor node ids. */
public record CfgNode(int id, Node astNode, List<Integer> successors) {
    public String code() {
        return astNode.toString();
    }
}
