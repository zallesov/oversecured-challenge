package com.oversecured.sast.misconfig.model;

import java.util.ArrayList;
import java.util.List;

public class MisconfigRuleFile {
    private int version;
    private List<MisconfigCheck> checks = new ArrayList<>();

    public MisconfigRuleFile() {
    }

    public MisconfigRuleFile(int version, List<MisconfigCheck> checks) {
        this.version = version;
        this.checks = checks == null ? List.of() : List.copyOf(checks);
    }

    public int getVersion() {
        return version;
    }

    public void setVersion(int version) {
        this.version = version;
    }

    public List<MisconfigCheck> getChecks() {
        return checks;
    }

    public void setChecks(List<MisconfigCheck> checks) {
        this.checks = checks == null ? List.of() : List.copyOf(checks);
    }
}
