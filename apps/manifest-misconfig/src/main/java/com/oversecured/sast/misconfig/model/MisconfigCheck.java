package com.oversecured.sast.misconfig.model;

import com.oversecured.sast.common.Severity;

public class MisconfigCheck {
    private String id;
    private Severity severity;
    private String cwe;
    private String kind;
    private String message;

    public MisconfigCheck() {
    }

    public MisconfigCheck(String id, Severity severity, String cwe, String kind, String message) {
        this.id = id;
        this.severity = severity;
        this.cwe = cwe;
        this.kind = kind;
        this.message = message;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public Severity getSeverity() {
        return severity;
    }

    public void setSeverity(Severity severity) {
        this.severity = severity;
    }

    public String getCwe() {
        return cwe;
    }

    public void setCwe(String cwe) {
        this.cwe = cwe;
    }

    public String getKind() {
        return kind;
    }

    public void setKind(String kind) {
        this.kind = kind;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
