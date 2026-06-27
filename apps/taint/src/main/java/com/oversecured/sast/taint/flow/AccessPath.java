package com.oversecured.sast.taint.flow;

/** A shallow taint key: a variable {@code v} or one-level field {@code v.f}. */
public record AccessPath(String key) {
    public static AccessPath of(String name) {
        return new AccessPath(name);
    }

    public static AccessPath field(String base, String field) {
        return new AccessPath(base + "." + field);
    }
}
