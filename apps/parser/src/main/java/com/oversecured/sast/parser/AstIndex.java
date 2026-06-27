package com.oversecured.sast.parser;

import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.symbolsolver.JavaSymbolSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.CombinedTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.JavaParserTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.ReflectionTypeSolver;
import com.github.javaparser.utils.SourceRoot;
import com.oversecured.sast.common.Diagnostics;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

/**
 * Parse-once AST + symbol index over a decompiled Java source tree.
 *
 * <p>This is the parser module's public library boundary, consumed in-process by {@code apps/taint}
 * and by the {@code parse} CLI. {@link #build(Path)} configures JavaParser with a
 * {@link CombinedTypeSolver} ({@link ReflectionTypeSolver} + {@link JavaParserTypeSolver}) and a
 * {@link JavaSymbolSolver}, then parses every {@code .java} file fail-soft (noclasspath-style):
 * unparseable files are skipped and unresolved types never abort the build.
 */
public final class AstIndex {

    private static final Logger log = LoggerFactory.getLogger(AstIndex.class);

    /** Function emoji for the build boundary (logging conventions §5). */
    private static final String FN_BUILD = "🌳"; // 🌳

    private final Path sourcesDir;
    private final List<CompilationUnit> units;

    private AstIndex(Path sourcesDir, List<CompilationUnit> units) {
        this.sourcesDir = sourcesDir;
        this.units = List.copyOf(units);
    }

    /**
     * Parse every {@code .java} file under {@code sourcesDir} with symbol resolution.
     *
     * <p>Fail-soft (noclasspath-style): unparseable files are recorded as recoverable
     * {@link Diagnostics} and skipped; unresolved types never abort the build. This boundary never
     * throws on broken individual files or unresolved Android types (error-handling conventions §4).
     */
    public static AstIndex build(Path sourcesDir) {
        Path root = sourcesDir.toAbsolutePath().normalize();
        log.info("{} ▶️ build ast-index from {}", FN_BUILD, root); // ▶️

        CombinedTypeSolver typeSolver = new CombinedTypeSolver();
        typeSolver.add(new ReflectionTypeSolver());
        typeSolver.add(new JavaParserTypeSolver(root));

        ParserConfiguration config = new ParserConfiguration()
            .setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_17)
            .setSymbolResolver(new JavaSymbolSolver(typeSolver));

        SourceRoot sourceRoot = new SourceRoot(root, config);
        Diagnostics diagnostics = new Diagnostics();
        try {
            // tryToParse records broken files as unsuccessful ParseResults instead of throwing;
            // only successful units land in getCompilationUnits(), so broken files are skipped.
            List<ParseResult<CompilationUnit>> results = sourceRoot.tryToParse();
            for (ParseResult<CompilationUnit> r : results) {
                if (!r.isSuccessful()) {
                    diagnostics.add(r.toString(), "unparseable source skipped");
                }
            }
        } catch (Exception e) {
            // Never abort the whole index because of I/O or a pathological file; fall through with
            // whatever was parsed and record the problem as recoverable.
            diagnostics.add(root.toString(), "parse sweep error: " + e.getMessage());
        }

        List<CompilationUnit> units = sourceRoot.getCompilationUnits();
        if (!diagnostics.isEmpty()) {
            log.warn("{} ⚠️ skipped {} unparseable file(s)", FN_BUILD, diagnostics.count()); // ⚠️
        }
        log.info("{} ✅ parsed {} compilation unit(s)", FN_BUILD, units.size()); // ✅
        return new AstIndex(root, units);
    }

    public List<CompilationUnit> units() {
        return units;
    }

    Path sourcesDir() {
        return sourcesDir;
    }

    public void save(Path indexDir) {
        throw new UnsupportedOperationException("implemented in Task 4");
    }

    public static AstIndex load(Path indexDir) {
        throw new UnsupportedOperationException("implemented in Task 4");
    }

    public Optional<String> resolveSignature(MethodCallExpr call) {
        throw new UnsupportedOperationException("implemented in Task 3");
    }
}
