package com.oversecured.sast.common;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses FlowDroid/Soot-style signatures: {@code <fqcn: ret name(p,p,...)>}.
 * Inner classes use '$'; the method name may be {@code <init>} or {@code <clinit>}.
 */
public final class SignatureParser {

    // <  class  :  ret  name  ( params )  >
    private static final Pattern SIG = Pattern.compile(
            "^<([^:]+):\\s+(\\S+)\\s+(<init>|<clinit>|[\\w$]+)\\((.*)\\)>$");

    private SignatureParser() {
    }

    public static MethodSignature parse(String sig) {
        if (sig == null) {
            throw new IllegalArgumentException("malformed signature: null");
        }
        Matcher m = SIG.matcher(sig.trim());
        if (!m.matches()) {
            throw new IllegalArgumentException("malformed signature: " + sig);
        }
        String declaringClass = m.group(1).trim();
        String returnType = m.group(2).trim();
        String name = m.group(3).trim();
        String paramBlob = m.group(4).trim();

        List<String> params = paramBlob.isEmpty()
                ? List.of()
                : List.of(paramBlob.split("\\s*,\\s*"));

        return new MethodSignature(declaringClass, returnType, name, params);
    }
}
