package com.oversecured.sast.parser;

import static org.assertj.core.api.Assertions.assertThat;

import com.github.javaparser.ast.expr.MethodCallExpr;
import com.oversecured.sast.parser.cli.ParseCommand;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ParserEndToEndTest {

    /** Repo root = two levels above the apps/parser module working dir. */
    private static Path repoRoot() {
        return Paths.get(System.getProperty("user.dir")).getParent().getParent();
    }

    private static Path ovaaSources() {
        return repoRoot()
            .resolve("test-subjects/source/ovaa/app/src/main/java");
    }

    @Test
    void cliParsesRealOvaaSourcesFailSoftAndReloads(@TempDir Path out) {
        Path src = ovaaSources();
        assertThat(Files.isDirectory(src))
            .as("real OVAA sources must exist at %s", src)
            .isTrue();

        // build() over real sources with many unresolved android.* types must NOT throw.
        int code = ParseCommand.run("--src", src.toString(), "--out", out.toString());
        assertThat(code).isZero();

        AstIndex reloaded = AstIndex.load(out);
        assertThat(reloaded.units())
            .as("fail-soft parse still yields compilation units")
            .isNotEmpty();
        // WebViewActivity is one of the real OVAA classes; it must have parsed.
        assertThat(reloaded.units())
            .anySatisfy(cu ->
                assertThat(cu.getPrimaryTypeName()).hasValue("WebViewActivity"));
    }

    @Test
    void resolvesDeterministicFixtureSignatureWithoutAndroidJar() {
        Path fixture = Paths.get("src", "test", "resources", "fixtures", "simple");

        AstIndex index = AstIndex.build(fixture);
        MethodCallExpr loadUrl = index.units().stream()
            .flatMap(cu -> cu.findAll(MethodCallExpr.class).stream())
            .filter(c -> c.getNameAsString().equals("loadUrl"))
            .findFirst()
            .orElseThrow();

        Optional<String> sig = index.resolveSignature(loadUrl);
        assertThat(sig).isPresent();
        assertThat(sig.get())
            .contains("com.example.web.WebView")
            .contains("loadUrl");
    }

    @Test
    void roundTripOverRealSourcesPreservesUnitCount(@TempDir Path out) {
        Path src = ovaaSources();
        assertThat(Files.isDirectory(src)).isTrue();

        AstIndex built = AstIndex.build(src);
        built.save(out);
        AstIndex loaded = AstIndex.load(out);

        assertThat(loaded.units()).hasSameSizeAs(built.units());
    }
}
