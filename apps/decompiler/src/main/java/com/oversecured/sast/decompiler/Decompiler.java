package com.oversecured.sast.decompiler;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Decompiles an APK into a Java source tree + decoded AndroidManifest.xml using embedded jadx. */
public final class Decompiler {

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
}
