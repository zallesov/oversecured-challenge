package com.oversecured.sast.common;

import java.util.List;

/** Top-level findings.json document produced by an analyzer (spec §7.1). */
public record FindingsDoc(String analyzer, List<Finding> findings) {
}
