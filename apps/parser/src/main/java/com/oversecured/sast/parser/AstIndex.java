package com.oversecured.sast.parser;

import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.resolution.declarations.ResolvedMethodDeclaration;
import com.github.javaparser.symbolsolver.JavaSymbolSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.CombinedTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.JavaParserTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.ReflectionTypeSolver;
import com.github.javaparser.utils.SourceRoot;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.oversecured.sast.common.Diagnostics;
import com.oversecured.sast.common.FailureKind;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
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
    /** Function emoji for the save boundary (logging conventions §5). */
    private static final String FN_SAVE = "💾"; // 💾
    /** Function emoji for the load boundary (logging conventions §5). */
    private static final String FN_LOAD = "📂"; // 📂

    private static final ObjectMapper MAPPER = new ObjectMapper();

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

    /**
     * Persist the index. JavaParser ASTs hold non-serializable resolver state and parent links, so
     * persisting them natively is impractical. This writes only a JSON descriptor of the source set
     * + solver config; {@link #load(Path)} re-parses from it. Tradeoff: <b>parse-once-per-run</b>
     * (build then save within a run is cheap to reproduce), <b>load re-parses</b> the original
     * {@code sources/}, which must remain available to the downstream taint step (spec §3.5).
     *
     * <p>Service boundary: an IO write fault is environmental and surfaced as
     * {@link ParserException} (TRANSIENT) per error-handling conventions §3.
     */
    public void save(Path indexDir) {
        try {
            Files.createDirectories(indexDir);
            IndexMeta meta = new IndexMeta(
                IndexMeta.CURRENT_VERSION,
                sourcesDir.toString(),
                ParserConfiguration.LanguageLevel.JAVA_17.name());
            MAPPER.writerWithDefaultPrettyPrinter()
                .writeValue(indexDir.resolve("index-meta.json").toFile(), meta);
            log.info("{} 📁 wrote ast-index descriptor to {}", FN_SAVE, indexDir); // 📁
        } catch (IOException e) {
            throw new ParserException(FailureKind.TRANSIENT,
                "failed to write ast-index to " + indexDir + " (" + e.getMessage() + ")", e);
        }
    }

    /**
     * Re-parse the sources described by {@code indexDir/index-meta.json}. A missing/corrupt
     * descriptor is a deterministic input fault surfaced as {@link ParserException} (PERMANENT).
     */
    public static AstIndex load(Path indexDir) {
        log.info("{} ▶️ load ast-index from {}", FN_LOAD, indexDir); // ▶️
        try {
            IndexMeta meta = MAPPER.readValue(
                indexDir.resolve("index-meta.json").toFile(), IndexMeta.class);
            return build(Path.of(meta.sourcesDir()));
        } catch (IOException e) {
            throw new ParserException(FailureKind.PERMANENT,
                "failed to read ast-index from " + indexDir + " (" + e.getMessage() + ")", e);
        }
    }

    /**
     * Resolve {@code call} to a FlowDroid/Soot-style signature
     * {@code <fully.qualified.Class: ReturnType name(ParamType,...)>}, or {@link Optional#empty()}
     * when the receiver/method cannot be resolved. Deep helper: stays silent and never throws
     * (fail-soft, error-handling conventions §4).
     */
    public Optional<String> resolveSignature(MethodCallExpr call) {
        try {
            ResolvedMethodDeclaration decl = call.resolve();
            return Optional.of(toFlowDroidSignature(decl));
        } catch (RuntimeException e) {
            // UnsolvedSymbolException and any resolver failure -> fail-soft.
            return Optional.empty();
        }
    }

    private static String toFlowDroidSignature(ResolvedMethodDeclaration decl) {
        StringBuilder params = new StringBuilder();
        for (int i = 0; i < decl.getNumberOfParams(); i++) {
            if (i > 0) {
                params.append(',');
            }
            params.append(decl.getParam(i).getType().describe());
        }
        return "<" + decl.declaringType().getQualifiedName()
            + ": " + decl.getReturnType().describe()
            + " " + decl.getName()
            + "(" + params + ")>";
    }
}
