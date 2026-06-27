package com.oversecured.sast.parser;

import java.util.List;

/**
 * On-disk descriptor of an ast-index artifact (load re-parses from sourcesDir).
 * {@code classpath} carries resolution jars (e.g. android.jar) so {@code load} rebuilds with the
 * same symbol resolution the index was created with.
 */
public record IndexMeta(int version, String sourcesDir, String languageLevel, List<String> classpath) {
    public static final int CURRENT_VERSION = 2;

    /** Older metas (v1) carry no classpath; Jackson supplies null, normalize to empty. */
    public List<String> classpath() {
        return classpath == null ? List.of() : classpath;
    }
}
