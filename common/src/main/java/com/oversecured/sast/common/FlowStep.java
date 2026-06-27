package com.oversecured.sast.common;

/** One ordered step in a source-to-sink taint flow (spec §7). */
public record FlowStep(String file, int line, String label) {
}
