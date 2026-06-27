package com.oversecured.sast.decompiler;

/** Thrown when decompilation cannot proceed; carries a human-readable message for the CLI. */
public class DecompilerException extends RuntimeException {

    public DecompilerException(String message) {
        super(message);
    }

    public DecompilerException(String message, Throwable cause) {
        super(message, cause);
    }
}
