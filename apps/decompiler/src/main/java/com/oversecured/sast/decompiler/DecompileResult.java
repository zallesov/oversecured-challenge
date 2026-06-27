package com.oversecured.sast.decompiler;

import java.nio.file.Path;

/** Output locations of a decompile run. */
public record DecompileResult(Path sourcesDir, Path manifestFile) {
}
