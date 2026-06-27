package com.oversecured.sast.common;

import java.util.List;

/** Top-level facts.json document produced by the manifest-facts step (spec §3.4). */
public record ManifestFacts(
        String packageName,
        List<ComponentFact> components,
        List<String> permissions) {
}
