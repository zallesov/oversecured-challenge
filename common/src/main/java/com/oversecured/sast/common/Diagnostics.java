package com.oversecured.sast.common;

import java.util.ArrayList;
import java.util.List;

/** Accumulates per-item, recoverable problems during a fail-soft step. */
public final class Diagnostics {

    public record Item(String where, String detail) {
    }

    private final List<Item> items = new ArrayList<>();

    public void add(String where, String detail) {
        items.add(new Item(where, detail));
    }

    public List<Item> items() {
        return List.copyOf(items);
    }

    public boolean isEmpty() {
        return items.isEmpty();
    }

    public int count() {
        return items.size();
    }
}
