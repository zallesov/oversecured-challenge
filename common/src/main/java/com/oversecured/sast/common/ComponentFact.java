package com.oversecured.sast.common;

import java.util.List;

/**
 * One manifest component. {@code type} is one of: activity, service, receiver, provider.
 * {@code grantUriPermissions} is the provider android:grantUriPermissions flag.
 * {@code permission} is the component's android:permission, or null if none.
 */
public record ComponentFact(
        String name,
        String type,
        boolean exported,
        List<IntentFilterFact> intentFilters,
        boolean grantUriPermissions,
        String permission) {
}
