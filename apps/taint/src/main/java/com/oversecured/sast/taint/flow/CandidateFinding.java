package com.oversecured.sast.taint.flow;

import com.oversecured.sast.common.FlowStep;
import java.util.List;

/** An internal candidate finding before reachability filtering and normalization to {@code Finding}. */
public final class CandidateFinding {
    private final String ruleId;
    private final String sourceComponent;
    private final List<FlowStep> flow;
    private final List<String> notes;

    public CandidateFinding(String ruleId, String sourceComponent, List<FlowStep> flow, List<String> notes) {
        this.ruleId = ruleId;
        this.sourceComponent = sourceComponent;
        this.flow = List.copyOf(flow);
        this.notes = List.copyOf(notes);
    }

    /** Test helper mirroring the production constructor. */
    public static CandidateFinding testOnly(String ruleId, String sourceComponent,
                                            List<FlowStep> flow, List<String> notes) {
        return new CandidateFinding(ruleId, sourceComponent, flow, notes);
    }

    public String ruleId() {
        return ruleId;
    }

    public String sourceComponent() {
        return sourceComponent;
    }

    public List<FlowStep> flow() {
        return flow;
    }

    public List<String> notes() {
        return notes;
    }

    /** Return a copy with an extra note appended. */
    public CandidateFinding withNote(String note) {
        List<String> next = new java.util.ArrayList<>(notes);
        next.add(note);
        return new CandidateFinding(ruleId, sourceComponent, flow, next);
    }
}
