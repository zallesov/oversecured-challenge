package com.oversecured.sast.taint.cfg;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.stmt.BlockStmt;
import com.github.javaparser.ast.stmt.ForEachStmt;
import com.github.javaparser.ast.stmt.ForStmt;
import com.github.javaparser.ast.stmt.IfStmt;
import com.github.javaparser.ast.stmt.Statement;
import com.github.javaparser.ast.stmt.SwitchEntry;
import com.github.javaparser.ast.stmt.SwitchStmt;
import com.github.javaparser.ast.stmt.TryStmt;
import com.github.javaparser.ast.stmt.WhileStmt;
import java.util.ArrayList;
import java.util.List;

/**
 * Builds a simple statement-level control-flow graph with conservative successor edges.
 * Supports sequential blocks, if/else, while/for/forEach loops, switch and try
 * conservatively; any unsupported statement becomes a single node to the next statement.
 */
public final class CfgBuilder {

    private final List<Node> astById = new ArrayList<>();
    private final List<List<Integer>> succById = new ArrayList<>();

    public ControlFlowGraph build(MethodDeclaration method) {
        astById.clear();
        succById.clear();

        int entry = method.getBody()
                .map(body -> buildSeq(body.getStatements(), -1))
                .orElseGet(() -> {
                    int id = addNode(method);
                    return id;
                });

        List<CfgNode> nodes = new ArrayList<>(astById.size());
        for (int i = 0; i < astById.size(); i++) {
            nodes.add(new CfgNode(i, astById.get(i), List.copyOf(succById.get(i))));
        }
        return new ControlFlowGraph(nodes, entry);
    }

    private int addNode(Node n) {
        int id = astById.size();
        astById.add(n);
        succById.add(new ArrayList<>());
        return id;
    }

    private void addEdge(int from, int to) {
        if (to >= 0) {
            succById.get(from).add(to);
        }
    }

    /** Build a statement sequence flowing into {@code next}; return the sequence entry id. */
    private int buildSeq(List<Statement> stmts, int next) {
        int cur = next;
        for (int i = stmts.size() - 1; i >= 0; i--) {
            cur = build(stmts.get(i), cur);
        }
        return cur;
    }

    /** Build one statement flowing into {@code next}; return its entry node id. */
    private int build(Statement stmt, int next) {
        if (stmt instanceof BlockStmt block) {
            return buildSeq(block.getStatements(), next);
        }
        if (stmt instanceof IfStmt ifStmt) {
            int cond = addNode(ifStmt.getCondition());
            int thenEntry = build(ifStmt.getThenStmt(), next);
            int elseEntry = ifStmt.getElseStmt().map(s -> build(s, next)).orElse(next);
            addEdge(cond, thenEntry);
            addEdge(cond, elseEntry);
            return cond;
        }
        if (stmt instanceof WhileStmt whileStmt) {
            int head = addNode(whileStmt);
            int bodyEntry = build(whileStmt.getBody(), head);
            addEdge(head, bodyEntry);
            addEdge(head, next);
            return head;
        }
        if (stmt instanceof ForStmt forStmt) {
            int head = addNode(forStmt);
            int bodyEntry = build(forStmt.getBody(), head);
            addEdge(head, bodyEntry);
            addEdge(head, next);
            return head;
        }
        if (stmt instanceof ForEachStmt forEach) {
            int head = addNode(forEach);
            int bodyEntry = build(forEach.getBody(), head);
            addEdge(head, bodyEntry);
            addEdge(head, next);
            return head;
        }
        if (stmt instanceof SwitchStmt switchStmt) {
            int head = addNode(switchStmt.getSelector());
            for (SwitchEntry entry : switchStmt.getEntries()) {
                int entryId = buildSeq(entry.getStatements(), next);
                addEdge(head, entryId);
            }
            addEdge(head, next);
            return head;
        }
        if (stmt instanceof TryStmt tryStmt) {
            int tryEntry = build(tryStmt.getTryBlock(), next);
            tryStmt.getCatchClauses()
                    .forEach(c -> addEdge(tryEntry, build(c.getBody(), next)));
            tryStmt.getFinallyBlock().ifPresent(f -> build(f, next));
            return tryEntry;
        }
        int id = addNode(stmt);
        addEdge(id, next);
        return id;
    }
}
