package com.oversecured.sast.aitriage;

import java.util.List;

public interface TriageEngine {
    TriageResult triage(List<TriageFinding> findings);

    String modelName();
}
