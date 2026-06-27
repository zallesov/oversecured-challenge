package com.oversecured.sast.taint.cfg;

import static org.assertj.core.api.Assertions.assertThat;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.body.MethodDeclaration;
import org.junit.jupiter.api.Test;

class CfgBuilderTest {
    @Test
    void ifStatementBranchesJoinBeforeSink() {
        MethodDeclaration method = StaticJavaParser.parseMethodDeclaration("""
                void m(boolean b) {
                    String x = "safe";
                    if (b) {
                        x = source();
                    } else {
                        x = "other";
                    }
                    sink(x);
                }
                """);

        ControlFlowGraph cfg = new CfgBuilder().build(method);

        assertThat(cfg.nodes()).hasSizeGreaterThanOrEqualTo(5);
        CfgNode sink = cfg.nodes().stream()
                .filter(n -> n.code().contains("sink(x)"))
                .findFirst().orElseThrow();
        long incoming = cfg.nodes().stream()
                .filter(n -> n.successors().contains(sink.id()))
                .count();
        assertThat(incoming).isGreaterThanOrEqualTo(2);
    }

    @Test
    void loopHasBackEdgeAndExitEdge() {
        MethodDeclaration method = StaticJavaParser.parseMethodDeclaration("""
                void m(boolean b) {
                    String x = source();
                    while (b) {
                        x = x.concat("a");
                    }
                    sink(x);
                }
                """);

        ControlFlowGraph cfg = new CfgBuilder().build(method);

        CfgNode loop = cfg.nodes().stream()
                .filter(n -> n.code().startsWith("while"))
                .findFirst().orElseThrow();
        assertThat(loop.successors()).hasSizeGreaterThanOrEqualTo(2);
    }
}
