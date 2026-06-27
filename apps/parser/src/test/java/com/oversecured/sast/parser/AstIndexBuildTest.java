package com.oversecured.sast.parser;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import com.github.javaparser.ast.CompilationUnit;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.jupiter.api.Test;

class AstIndexBuildTest {

    private static Path fixture(String name) {
        return Paths.get("src", "test", "resources", "fixtures", name);
    }

    @Test
    void buildParsesAllWellFormedUnits() {
        AstIndex index = AstIndex.build(fixture("simple"));
        assertThat(index.units()).hasSize(2);
        assertThat(index.units())
            .extracting(cu -> cu.getPrimaryTypeName().orElseThrow())
            .containsExactlyInAnyOrder("WebView", "Caller");
    }

    @Test
    void buildIsFailSoftOnBrokenFiles() {
        // The broken fixture dir contains one unparseable file; build must not throw
        // and must simply omit the unparseable unit.
        assertThatCode(() -> {
            AstIndex index = AstIndex.build(fixture("broken"));
            assertThat(index.units()).isEmpty();
        }).doesNotThrowAnyException();
    }
}
