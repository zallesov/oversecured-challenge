package com.oversecured.sast.taint.rules;

import com.oversecured.sast.common.MethodSignature;
import com.oversecured.sast.common.SignatureParser;

/**
 * Bridges rule YAML signatures (which may be bare FlowDroid-style or bracketed)
 * to the shared {@link SignatureParser}, which requires bracketed form.
 */
public final class RuleSignatures {

    private RuleSignatures() {
    }

    /** Wrap a bare signature in angle brackets; leave an already-bracketed one untouched. */
    public static String canonical(String signature) {
        if (signature == null) {
            throw new IllegalArgumentException("malformed signature: null");
        }
        String trimmed = signature.trim();
        if (trimmed.startsWith("<") && trimmed.endsWith(">")) {
            return trimmed;
        }
        return "<" + trimmed + ">";
    }

    /** Canonicalize then parse via the shared parser. */
    public static MethodSignature parseMethod(String signature) {
        return SignatureParser.parse(canonical(signature));
    }
}
