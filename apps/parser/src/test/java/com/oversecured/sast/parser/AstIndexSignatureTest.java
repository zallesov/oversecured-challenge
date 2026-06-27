package com.oversecured.sast.parser;

import static org.assertj.core.api.Assertions.assertThat;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.MethodCallExpr;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class AstIndexSignatureTest {

    private static Path fixture(String name) {
        return Paths.get("src", "test", "resources", "fixtures", name);
    }

    private static MethodCallExpr firstCall(AstIndex index, String methodName) {
        return index.units().stream()
            .flatMap(cu -> cu.findAll(MethodCallExpr.class).stream())
            .filter(c -> c.getNameAsString().equals(methodName))
            .findFirst()
            .orElseThrow();
    }

    @Test
    void resolvesUserDefinedCallToFlowDroidSignature() {
        AstIndex index = AstIndex.build(fixture("simple"));
        MethodCallExpr call = firstCall(index, "loadUrl");

        Optional<String> sig = index.resolveSignature(call);

        assertThat(sig).isPresent();
        assertThat(sig.get())
            .isEqualTo("<com.example.web.WebView: void loadUrl(java.lang.String)>");
    }

    @Test
    void returnsEmptyForUnresolvableCall() {
        AstIndex index = AstIndex.build(fixture("unresolved"));
        MethodCallExpr call = firstCall(index, "doStuff");

        assertThat(index.resolveSignature(call)).isEmpty();
    }
}
