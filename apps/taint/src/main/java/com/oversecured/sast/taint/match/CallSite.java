package com.oversecured.sast.taint.match;

import com.github.javaparser.ast.expr.Expression;
import java.util.List;
import java.util.Optional;

/** A resolved method call: its canonical signature, location, receiver, and arguments. */
public record CallSite(
        String resolvedSignature,
        String file,
        int line,
        Optional<Expression> receiver,
        List<Expression> arguments) {
}
