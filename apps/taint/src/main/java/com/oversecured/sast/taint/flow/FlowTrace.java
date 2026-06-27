package com.oversecured.sast.taint.flow;

import com.oversecured.sast.common.FlowStep;
import java.util.ArrayList;
import java.util.List;

/** An ordered source-to-sink path under construction, plus any annotations (notes). */
public final class FlowTrace {
    private final List<FlowStep> steps;
    private final List<String> notes;

    public FlowTrace() {
        this(List.of(), List.of());
    }

    private FlowTrace(List<FlowStep> steps, List<String> notes) {
        this.steps = List.copyOf(steps);
        this.notes = List.copyOf(notes);
    }

    public FlowTrace addStep(FlowStep step) {
        List<FlowStep> next = new ArrayList<>(steps);
        next.add(step);
        return new FlowTrace(next, notes);
    }

    public FlowTrace addNote(String note) {
        List<String> next = new ArrayList<>(notes);
        next.add(note);
        return new FlowTrace(steps, next);
    }

    public List<FlowStep> steps() {
        return steps;
    }

    public List<String> notes() {
        return notes;
    }

    public int length() {
        return steps.size();
    }
}
