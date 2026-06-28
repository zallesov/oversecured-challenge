package com.oversecured.sast.aitriage;

import java.util.List;

public record TriageResult(String model, String generatedAt, String summary, List<TriageItem> items) {
}
