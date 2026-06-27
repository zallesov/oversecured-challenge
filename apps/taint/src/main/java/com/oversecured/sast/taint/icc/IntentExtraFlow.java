package com.oversecured.sast.taint.icc;

import com.oversecured.sast.common.FlowStep;

/**
 * A resolved Intent-extra ICC edge: a tainted {@code putExtra(key, ...)} in {@code sourceComponent}
 * that is dispatched (via {@code startActivity}/{@code startService}) to {@code targetComponent},
 * carrying the cross-component flow step.
 */
public record IntentExtraFlow(
        String key,
        String sourceComponent,
        String targetComponent,
        FlowStep putExtraStep) {
}
