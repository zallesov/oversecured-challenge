package com.oversecured.sast.misconfig;

import com.oversecured.sast.common.ComponentFact;
import com.oversecured.sast.common.Finding;
import com.oversecured.sast.common.FindingsDoc;
import com.oversecured.sast.common.FlowStep;
import com.oversecured.sast.common.IntentFilterFact;
import com.oversecured.sast.common.ManifestFacts;
import com.oversecured.sast.misconfig.model.MisconfigCheck;
import com.oversecured.sast.misconfig.model.MisconfigRuleFile;
import java.util.ArrayList;
import java.util.List;

public class MisconfigAnalyzer {

    public FindingsDoc analyze(ManifestFacts facts, MisconfigRuleFile rules) {
        List<Finding> findings = new ArrayList<>();
        for (MisconfigCheck check : rules.getChecks()) {
            for (ComponentFact component : facts.components()) {
                if (matches(check.getId(), component)) {
                    findings.add(toFinding(check, component, notes(check.getId(), component)));
                }
            }
        }
        return new FindingsDoc("manifest-misconfig", List.copyOf(findings));
    }

    private boolean matches(String checkId, ComponentFact component) {
        return switch (checkId) {
            case "exported_without_permission" -> component.exported() && isBlank(component.permission());
            case "exported_provider" -> component.exported() && "provider".equals(component.type());
            case "provider_grant_uri_permissions" ->
                    "provider".equals(component.type()) && component.grantUriPermissions();
            case "weak_host_validation" -> component.exported() && hasWeakManifestHost(component);
            default -> false;
        };
    }

    private Finding toFinding(MisconfigCheck check, ComponentFact component, List<String> notes) {
        return new Finding(
                check.getId(),
                check.getKind(),
                check.getSeverity(),
                check.getMessage(),
                check.getCwe(),
                "M1",
                List.of(new FlowStep("AndroidManifest.xml", 0,
                        component.type() + " " + component.name() + " matches " + check.getId())),
                notes);
    }

    private List<String> notes(String checkId, ComponentFact component) {
        List<String> notes = new ArrayList<>();
        if ("provider_grant_uri_permissions".equals(checkId)) {
            notes.add("fact: grantUriPermissions=true");
        }
        if (isBlank(component.permission())) {
            notes.add("component-permission: none");
        } else {
            notes.add("component-permission: " + component.permission());
        }
        return List.copyOf(notes);
    }

    private boolean hasWeakManifestHost(ComponentFact component) {
        for (IntentFilterFact filter : component.intentFilters()) {
            if (filter.schemes().isEmpty()) {
                continue;
            }
            if (filter.hosts().isEmpty()) {
                return true;
            }
            for (String host : filter.hosts()) {
                if (isBlank(host) || "*".equals(host) || host.startsWith("*.")) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
