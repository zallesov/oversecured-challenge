package com.oversecured.sast.parser;

/** On-disk descriptor of an ast-index artifact (load re-parses from sourcesDir). */
public record IndexMeta(int version, String sourcesDir, String languageLevel) {
    public static final int CURRENT_VERSION = 1;
}
