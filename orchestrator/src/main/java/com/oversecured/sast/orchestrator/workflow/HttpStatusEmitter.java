package com.oversecured.sast.orchestrator.workflow;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * POSTs {@link StatusEvent} as JSON to the callback URL.
 * Best-effort: never throws. Timeout is 3 s.
 */
public final class HttpStatusEmitter implements StatusEmitter {

    private static final Logger LOG = Logger.getLogger(HttpStatusEmitter.class.getName());
    private static final Duration TIMEOUT = Duration.ofSeconds(3);

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public HttpStatusEmitter() {
        this(HttpClient.newBuilder().build(), new ObjectMapper());
    }

    HttpStatusEmitter(HttpClient httpClient, ObjectMapper objectMapper) {
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
    }

    @Override
    public void emit(CallbackContext ctx, StatusEvent event) {
        try {
            String body = objectMapper.writeValueAsString(event);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(ctx.url()))
                    .header("Content-Type", "application/json")
                    .header("X-Callback-Secret", ctx.secret() != null ? ctx.secret() : "")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .timeout(TIMEOUT)
                    .build();
            httpClient.sendAsync(request, HttpResponse.BodyHandlers.discarding()).get(3, TimeUnit.SECONDS);
        } catch (Throwable t) {
            LOG.log(Level.FINE, "Status emit failed (best-effort, ignored)", t);
        }
    }
}
