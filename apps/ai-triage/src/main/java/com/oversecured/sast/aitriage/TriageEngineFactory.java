package com.oversecured.sast.aitriage;

import java.nio.file.Path;

@FunctionalInterface
public interface TriageEngineFactory {
    /** Returns an engine for this sources root, or null if unavailable (e.g. no API key). */
    TriageEngine create(Path sourcesDir);
}
