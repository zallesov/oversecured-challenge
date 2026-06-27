package com.oversecured.sast.parser;

import static org.assertj.core.api.Assertions.assertThat;

import com.github.javaparser.StaticJavaParser;
import org.junit.jupiter.api.Test;

class BuildSmokeTest {
    @Test
    void toolchainAndDependenciesAreOnClasspath() {
        // Proves JavaParser is resolvable and JUnit5 + AssertJ run.
        var cu = StaticJavaParser.parse("class A { void m() {} }");
        assertThat(cu.getType(0).getNameAsString()).isEqualTo("A");
    }
}
