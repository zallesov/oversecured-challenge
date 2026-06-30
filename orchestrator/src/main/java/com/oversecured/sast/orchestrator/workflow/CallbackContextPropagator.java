package com.oversecured.sast.orchestrator.workflow;

import io.temporal.api.common.v1.Payload;
import io.temporal.common.context.ContextPropagator;
import io.temporal.common.converter.GlobalDataConverter;

import java.util.HashMap;
import java.util.Map;

/**
 * Propagates {@link CallbackContext} as Temporal headers from workflow to activity.
 * Header keys: callbackUrl, callbackSecret, runId.
 */
public final class CallbackContextPropagator implements ContextPropagator {

    public static final String URL = "callbackUrl";
    public static final String SECRET = "callbackSecret";
    public static final String RUN_ID = "runId";

    private static final ThreadLocal<CallbackContext> HOLDER = new ThreadLocal<>();

    @Override
    public String getName() {
        return "callback";
    }

    @Override
    public Map<String, Payload> serializeContext(Object context) {
        if (!(context instanceof CallbackContext ctx) || !ctx.isPresent()) {
            return Map.of();
        }
        Map<String, Payload> result = new HashMap<>();
        if (ctx.url() != null) {
            GlobalDataConverter.get().toPayload(ctx.url()).ifPresent(p -> result.put(URL, p));
        }
        if (ctx.secret() != null) {
            GlobalDataConverter.get().toPayload(ctx.secret()).ifPresent(p -> result.put(SECRET, p));
        }
        if (ctx.runId() != null) {
            GlobalDataConverter.get().toPayload(ctx.runId()).ifPresent(p -> result.put(RUN_ID, p));
        }
        return result;
    }

    @Override
    public Object deserializeContext(Map<String, Payload> header) {
        if (header == null || header.isEmpty()) {
            return new CallbackContext(null, null, null);
        }
        String url = readString(header, URL);
        String secret = readString(header, SECRET);
        String runId = readString(header, RUN_ID);
        return new CallbackContext(url, secret, runId);
    }

    @Override
    public Object getCurrentContext() {
        return HOLDER.get();
    }

    @Override
    public void setCurrentContext(Object context) {
        HOLDER.set((CallbackContext) context);
    }

    /** Returns the current {@link CallbackContext} for this thread (may be null). */
    public static CallbackContext current() {
        return HOLDER.get();
    }

    private static String readString(Map<String, Payload> header, String key) {
        Payload payload = header.get(key);
        if (payload == null) {
            return null;
        }
        try {
            return GlobalDataConverter.get().fromPayload(payload, String.class, String.class);
        } catch (Exception e) {
            return null;
        }
    }
}
