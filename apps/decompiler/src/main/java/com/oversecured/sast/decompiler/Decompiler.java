package com.oversecured.sast.decompiler;

import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

/** Decompiles an APK into a Java source tree + decoded AndroidManifest.xml using embedded jadx. */
public final class Decompiler {

    /**
     * Decompiles {@code apk} into {@code outDir}: jadx writes the .java package tree and the
     * decoded AndroidManifest.xml directly into {@code outDir} (the CLI's --out is the sources dir).
     *
     * @throws DecompilerException on bad input, jadx failure, or when no .java sources are produced.
     */
    public DecompileResult decompile(Path apk, Path outDir) {
        validate(apk);

        try {
            Files.createDirectories(outDir);
        } catch (IOException e) {
            throw new DecompilerException("cannot create output dir: " + outDir + " (" + e.getMessage() + ")", e);
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
            throw new DecompilerException("jadx failed to decompile: " + apk + " (" + e.getMessage() + ")", e);
        }

        if (!hasJavaFile(outDir)) {
            throw new DecompilerException(
                    "decompilation produced no .java sources for: " + apk + " (corrupt or unsupported APK?)");
        }

        return new DecompileResult(outDir, outDir.resolve("AndroidManifest.xml"));
    }

    /**
     * Validates that {@code apk} is a readable, non-empty regular file.
     *
     * @throws DecompilerException with a clear message otherwise.
     */
    void validate(Path apk) {
        if (apk == null) {
            throw new DecompilerException("apk path is null");
        }
        if (!Files.exists(apk)) {
            throw new DecompilerException("apk not found: " + apk);
        }
        if (!Files.isRegularFile(apk)) {
            throw new DecompilerException("apk is not a regular file: " + apk);
        }
        try {
            if (Files.size(apk) == 0) {
                throw new DecompilerException("apk is empty: " + apk);
            }
        } catch (IOException e) {
            throw new DecompilerException("cannot read apk: " + apk + " (" + e.getMessage() + ")", e);
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
