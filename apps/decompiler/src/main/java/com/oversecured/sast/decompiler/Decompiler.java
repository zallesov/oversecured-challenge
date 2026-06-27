package com.oversecured.sast.decompiler;

import com.oversecured.sast.common.FailureKind;

import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

/** Decompiles an APK into a Java source tree + decoded AndroidManifest.xml using embedded jadx. */
public final class Decompiler {

    private static final Logger log = LoggerFactory.getLogger(Decompiler.class);

    /** Function emoji for this boundary (logging conventions §5). */
    private static final String FN = "🔨"; // 🔨

    /**
     * Decompiles {@code apk} into {@code outDir}: jadx writes the .java package tree and the
     * decoded AndroidManifest.xml directly into {@code outDir} (the CLI's --out is the sources dir).
     *
     * <p>This is the module service boundary: it logs lifecycle, translates raw failures into
     * {@link DecompilerException} with an explicit {@link FailureKind}, and lets deep helpers stay
     * silent (error-handling conventions §3).
     *
     * @throws DecompilerException on bad input, jadx failure, or when no .java sources are produced.
     */
    public DecompileResult decompile(Path apk, Path outDir) {
        validate(apk);
        log.info("{} ▶️ decompiling {}", FN, apk); // ▶️

        try {
            Files.createDirectories(outDir);
        } catch (IOException e) {
            // Output filesystem fault is environmental -> retryable.
            throw new DecompilerException(FailureKind.TRANSIENT,
                    "cannot create output dir: " + outDir + " (" + e.getMessage() + ")", e);
        }

        JadxArgs args = new JadxArgs();
        args.setInputFiles(List.of(apk.toFile()));
        // --out is the output dir itself: emit sources AND resources (incl. manifest) into it.
        args.setOutDir(outDir.toFile());
        args.setOutDirSrc(outDir.toFile());
        args.setOutDirRes(outDir.toFile());

        try (JadxDecompiler jadx = new JadxDecompiler(args)) {
            jadx.load();
            jadx.save();
        } catch (RuntimeException e) {
            // jadx fails deterministically on a corrupt/unsupported APK -> not retryable.
            throw new DecompilerException(FailureKind.PERMANENT,
                    "jadx failed to decompile: " + apk + " (" + e.getMessage() + ")", e);
        }

        if (!hasJavaFile(outDir)) {
            throw new DecompilerException(FailureKind.PERMANENT,
                    "decompilation produced no .java sources for: " + apk + " (corrupt or unsupported APK?)");
        }

        log.info("{} 📁 wrote sources + AndroidManifest.xml to {}", FN, outDir); // 📁
        return new DecompileResult(outDir, outDir.resolve("AndroidManifest.xml"));
    }

    /**
     * Validates that {@code apk} is a readable, non-empty regular file. Bad input is always a
     * PERMANENT failure (retrying will not help).
     *
     * @throws DecompilerException with a clear message otherwise.
     */
    void validate(Path apk) {
        if (apk == null) {
            throw new DecompilerException(FailureKind.PERMANENT, "apk path is null");
        }
        if (!Files.exists(apk)) {
            throw new DecompilerException(FailureKind.PERMANENT, "apk not found: " + apk);
        }
        if (!Files.isRegularFile(apk)) {
            throw new DecompilerException(FailureKind.PERMANENT, "apk is not a regular file: " + apk);
        }
        try {
            if (Files.size(apk) == 0) {
                throw new DecompilerException(FailureKind.PERMANENT, "apk is empty: " + apk);
            }
        } catch (IOException e) {
            throw new DecompilerException(FailureKind.TRANSIENT,
                    "cannot read apk: " + apk + " (" + e.getMessage() + ")", e);
        }
    }

    private static boolean hasJavaFile(Path dir) {
        try (Stream<Path> s = Files.walk(dir)) {
            return s.anyMatch(p -> p.toString().endsWith(".java"));
        } catch (IOException e) {
            return false;
        }
    }
}
