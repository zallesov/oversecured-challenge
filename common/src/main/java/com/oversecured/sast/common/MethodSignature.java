package com.oversecured.sast.common;

import java.util.List;

/** A FlowDroid/Soot-style method reference (spec §5). Inner classes use '$'. */
public record MethodSignature(
        String declaringClass,
        String returnType,
        String name,
        List<String> paramTypes) {
}
