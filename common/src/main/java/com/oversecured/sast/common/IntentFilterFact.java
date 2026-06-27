package com.oversecured.sast.common;

import java.util.List;

/** One <intent-filter> reduced to its attack-surface facts (spec §3.4). */
public record IntentFilterFact(List<String> actions, List<String> schemes, List<String> hosts) {
}
