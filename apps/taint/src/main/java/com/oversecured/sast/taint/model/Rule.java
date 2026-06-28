package com.oversecured.sast.taint.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.oversecured.sast.common.Severity;
import java.util.List;

/** One taint rule: metadata, manifest conditions, sources, sinks, sanitizers, propagators. */
public final class Rule {
    private final String id;
    private final String vulnerabilityClass;
    private final Severity severity;
    private final String cwe;
    private final String owaspMobile;
    private final String message;
    private final ManifestConditions manifestConditions;
    private final List<SourceSpec> sources;
    private final List<SinkSpec> sinks;
    private final List<SanitizerSpec> sanitizers;
    private final List<String> propagators;
    private final List<String> carriers;

    @JsonCreator
    public Rule(
            @JsonProperty("id") String id,
            @JsonProperty("vulnerability_class") String vulnerabilityClass,
            @JsonProperty("severity") Severity severity,
            @JsonProperty("cwe") String cwe,
            @JsonProperty("owasp_mobile") String owaspMobile,
            @JsonProperty("message") String message,
            @JsonProperty("manifest_conditions") ManifestConditions manifestConditions,
            @JsonProperty("sources") List<SourceSpec> sources,
            @JsonProperty("sinks") List<SinkSpec> sinks,
            @JsonProperty("sanitizers") List<SanitizerSpec> sanitizers,
            @JsonProperty("propagators") List<String> propagators,
            @JsonProperty("carriers") List<String> carriers) {
        this.id = id;
        this.vulnerabilityClass = vulnerabilityClass;
        this.severity = severity;
        this.cwe = cwe;
        this.owaspMobile = owaspMobile;
        this.message = message;
        this.manifestConditions = manifestConditions;
        this.sources = sources == null ? List.of() : List.copyOf(sources);
        this.sinks = sinks == null ? List.of() : List.copyOf(sinks);
        this.sanitizers = sanitizers == null ? List.of() : List.copyOf(sanitizers);
        this.propagators = propagators == null ? List.of() : List.copyOf(propagators);
        this.carriers = carriers == null ? List.of() : List.copyOf(carriers);
    }

    /** Convenience overload for callers that predate carriers (no carrier methods). */
    public Rule(
            String id, String vulnerabilityClass, Severity severity, String cwe, String owaspMobile,
            String message, ManifestConditions manifestConditions, List<SourceSpec> sources,
            List<SinkSpec> sinks, List<SanitizerSpec> sanitizers, List<String> propagators) {
        this(id, vulnerabilityClass, severity, cwe, owaspMobile, message, manifestConditions,
                sources, sinks, sanitizers, propagators, List.of());
    }

    public String getId() {
        return id;
    }

    public String getVulnerabilityClass() {
        return vulnerabilityClass;
    }

    public Severity getSeverity() {
        return severity;
    }

    public String getCwe() {
        return cwe;
    }

    public String getOwaspMobile() {
        return owaspMobile;
    }

    public String getMessage() {
        return message;
    }

    public ManifestConditions getManifestConditions() {
        return manifestConditions;
    }

    public List<SourceSpec> getSources() {
        return sources;
    }

    public List<SinkSpec> getSinks() {
        return sinks;
    }

    public List<SanitizerSpec> getSanitizers() {
        return sanitizers;
    }

    public List<String> getPropagators() {
        return propagators;
    }

    /** Methods that taint their receiver object when an argument is tainted (e.g. Intent.putExtra). */
    public List<String> getCarriers() {
        return carriers;
    }
}
