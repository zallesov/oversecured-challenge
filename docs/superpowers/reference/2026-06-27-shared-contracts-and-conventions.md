# Shared Contracts and Naming Conventions

**Date:** 2026-06-27
**Status:** Required reference for implementation plans
**Audience:** agents and developers implementing individual Android Taint SAST pipeline modules

This document is the source of truth for names, shared types, artifact communication, and ownership boundaries across the pipeline. Every step-specific plan must follow it unless that plan explicitly documents a deliberate exception.

---

## 1. Goals

Use this document to keep independently implemented steps compatible:

- One package naming scheme across all modules.
- One place for shared cross-step types.
- One artifact communication model between steps.
- Clear ownership of analyzer-specific models.
- No duplicate copies of shared contracts in step modules.

This is a reference document. It does not define taint-analysis behavior, UI/report styling, or step-specific implementation algorithms.

---

## 2. Module and Package Naming

### 2.1 Gradle module names

Canonical Gradle modules:

| Module | Purpose |
|---|---|
| `:common` | Shared contracts, serialization helpers, artifact-store interfaces, signatures, manifest facts, findings. |
| `:apps:decompiler` | APK to decompiled Java sources and manifest. |
| `:apps:parser` | Java source tree to AST/symbol index artifact. |
| `:apps:manifest-facts` | AndroidManifest.xml to shared `facts.json`. |
| `:apps:taint` | Rule-driven taint/dataflow engine. |
| `:apps:manifest-misconfig` | Rule-driven manifest misconfiguration analyzer. |
| `:apps:reporter` | Findings fan-in to HTML and SARIF. |
| `:orchestrator` | Temporal workflow and activity wiring only. |
| `:benchmark` | DroidBench/OVAA fixtures, scoring, and E2E validation harness. |

The `common` foundation plan owns root `settings.gradle`, root `build.gradle`, Gradle wrapper, and shared dependency versions. Step plans must extend the canonical root build, not replace it with a step-only build.

### 2.2 Java package names

Use `com.oversecured.sast` as the package root.

| Module | Package root |
|---|---|
| `common` | `com.oversecured.sast.common` |
| `apps/decompiler` | `com.oversecured.sast.decompiler` |
| `apps/parser` | `com.oversecured.sast.parser` |
| `apps/manifest-facts` | `com.oversecured.sast.manifestfacts` |
| `apps/taint` | `com.oversecured.sast.taint` |
| `apps/manifest-misconfig` | `com.oversecured.sast.misconfig` |
| `apps/reporter` | `com.oversecured.sast.reporter` |
| `orchestrator` | `com.oversecured.sast.orchestrator` |
| `benchmark` | `com.oversecured.sast.benchmark` |

Do not create parallel shared packages such as `com.oversecured.sast.common.model`. Shared records live directly under `com.oversecured.sast.common` unless the common plan later introduces a documented subpackage.

---

## 3. Shared Type Ownership

### 3.1 What belongs in `common`

Put a type in `common` only when at least two independently runnable steps must exchange it or when it is part of a stable serialized artifact schema.

Canonical shared types:

| Type | Owner | Used by |
|---|---|---|
| `ArtifactStore` | `common` | all steps and orchestrator |
| `LocalFsStore` | `common` | local execution, tests, worker activities |
| `Json` | `common` | modules reading/writing shared JSON/YAML schemas |
| `FlowStep` | `common` | analyzers, reporter, SARIF/HTML output |
| `Severity` | `common` | rules, analyzers, reporter |
| `Finding` | `common` | taint, manifest-misconfig, reporter |
| `FindingsDoc` | `common` | analyzer outputs and reporter input |
| `IntentFilterFact` | `common` | manifest-facts, taint, manifest-misconfig |
| `ComponentFact` | `common` | manifest-facts, taint, manifest-misconfig |
| `ManifestFacts` | `common` | manifest-facts output and analyzer input |
| `MethodSignature` | `common` | rules validation, taint, parser/symbol matching |
| `SignatureParser` | `common` | rules validation, taint, tests |

### 3.2 What does not belong in `common`

Do not put these in `common`:

- Decompiled-source implementation details.
- JavaParser AST wrappers that only the parser and taint app use, unless they become a stable cross-step artifact contract.
- Taint worklist state, CFG nodes, taint states, method summaries, sanitizer internals.
- Manifest-misconfig check implementation details.
- Reporter HTML/SARIF rendering classes.
- Temporal workflow/activity classes.
- Benchmark scoring internals.

### 3.3 Analyzer-specific rule models

Analyzer rule models are owned by the analyzer modules, not by `common`.

| Model | Owner |
|---|---|
| `RuleFile`, `Rule`, `ManifestConditions`, `SourceSpec`, `SinkSpec`, `SanitizerSpec` | `apps/taint`, package `com.oversecured.sast.taint.model` |
| `MisconfigRuleFile`, `MisconfigCheck` | `apps/manifest-misconfig`, package `com.oversecured.sast.misconfig.model` |

Reason: these models describe analyzer policy configuration, not cross-step artifacts. The reporter receives normalized `FindingsDoc`, not analyzer-specific rule objects.

---

## 4. Inter-Step Communication

### 4.1 Artifact-first contract

Steps communicate through artifacts, not in-memory objects, stdout parsing, or direct module internals.

Every step must support:

- A CLI that reads input paths and writes output paths.
- A library API that the orchestrator can call in-process.
- Deterministic artifact output suitable for Temporal retries.

`ArtifactStore` is the common abstraction:

```java
package com.oversecured.sast.common;

public interface ArtifactStore {
    void put(String key, byte[] data);
    byte[] get(String key);
}
```

The challenge-default implementation is `LocalFsStore`. `S3Store` is future work unless explicitly added later.

### 4.2 Artifact keys and file names

Use stable, explicit artifact names. The orchestrator may prefix them by run id, but the logical names stay the same.

| Producer | Artifact | Consumer |
|---|---|---|
| `decompiler` | `sources/` | `parser`, tests |
| `decompiler` | `sources/AndroidManifest.xml` | `manifest-facts` |
| `parser` | `ast-index/` | `taint` |
| `manifest-facts` | `facts.json` | `taint`, `manifest-misconfig` |
| `taint` with `webview.yaml` | `findings-webview.json` | `reporter` |
| `taint` with `pathtraversal.yaml` | `findings-pathtraversal.json` | `reporter` |
| `manifest-misconfig` | `findings-misconfig.json` | `reporter` |
| `reporter` | `report.html` | final human output |
| `reporter` | `report.sarif` | final machine output |

Stdout is for human progress messages only. It is not a contract between steps.

### 4.3 Step contracts

Each runnable step must expose one CLI and one library API. The exact class names are owned by the step plan, but inputs and outputs must match this table.

| Step | CLI shape | Input artifacts | Output artifacts |
|---|---|---|---|
| `decompiler` | `decompile --apk <apk> --out <sourcesDir>` | APK file | `sources/`, `sources/AndroidManifest.xml` |
| `parser` | `parse --src <sourcesDir> --out <astIndexDir>` | `sources/` | `ast-index/` |
| `manifest-facts` | `mfacts --manifest <AndroidManifest.xml> --out <facts.json>` | manifest XML | `facts.json` |
| `taint` | `taint --ast <ast-index> --facts <facts.json> --rule <rule.yaml> --out <findings.json>` | `ast-index/`, `facts.json`, rule YAML | `findings.json` |
| `manifest-misconfig` | `mscan --facts <facts.json> --rule <misconfig.yaml> --out <findings.json>` | `facts.json`, rule YAML | `findings.json` |
| `reporter` | `report --findings <json...> --html <report.html> --sarif <report.sarif>` | one or more `findings*.json` | HTML, SARIF |

---

## 5. Serialized Schemas

### 5.1 JSON naming

Shared JSON artifacts use Jackson's default camelCase record/component names unless a plan explicitly says otherwise.

Examples:

- `ruleId`
- `vulnerabilityClass`
- `owaspMobile`
- `intentFilters`
- `packageName`

External YAML rule files use snake_case because they are user-authored policy files:

- `vulnerability_class`
- `owasp_mobile`
- `manifest_conditions`
- `reachable_from_exported`
- `tainted_args`

Rule loaders must configure YAML deserialization accordingly.

### 5.2 `findings.json`

`findings.json` is analyzer-agnostic and must deserialize into `FindingsDoc`.

Minimum shared shape:

```json
{
  "analyzer": "taint-engine",
  "findings": [
    {
      "ruleId": "ANDROID_WEBVIEW_INTENT_LOADURL",
      "vulnerabilityClass": "webview-open-redirect",
      "severity": "ERROR",
      "message": "Untrusted deeplink data flows into WebView.loadUrl",
      "cwe": "CWE-601",
      "owaspMobile": "M1",
      "flow": [
        {"file": "DeeplinkActivity.java", "line": 47, "label": "source"}
      ],
      "notes": []
    }
  ]
}
```

Analyzers may add explanatory details in `notes`, but they must not add analyzer-specific required fields to the reporter contract.

### 5.3 `facts.json`

`facts.json` is produced only by `manifest-facts` and consumed by analyzers. It must deserialize into `ManifestFacts`.

Required concepts:

- Android package name.
- Components with name, type, exported state, permission, and intent filters.
- Provider `grantUriPermissions` state as a first-class component fact.
- Intent-filter facts with actions, categories, data schemes, and data hosts.
- Manifest-level permissions when needed by analyzers.

The exact record component names are owned by the `common` plan and must remain stable once implemented.

---

## 6. Dependency and Build Conventions

The root build owns dependency versions in `ext`. Subprojects must reference those values:

- `rootProject.ext.jacksonVersion`
- `rootProject.ext.junitVersion`
- `rootProject.ext.assertjVersion`
- `rootProject.ext.picocliVersion`
- `rootProject.ext.javaparserVersion`

Do not hardcode duplicate dependency versions in step module build files unless the root does not yet expose the version and the plan also adds it to the root `ext` block.

Runnable step modules use the Gradle `application` plugin. `common` and `benchmark` are libraries.

---

## 7. Orchestrator Boundaries

The orchestrator wires steps; it does not implement analysis logic.

Allowed in `orchestrator`:

- Temporal workflow definition.
- Activity interfaces and activity implementations that call step library APIs.
- Artifact key planning.
- Fan-out/fan-in sequencing.
- Retry and timeout policy.

Not allowed in `orchestrator`:

- Taint propagation logic.
- Manifest parsing logic.
- Rule parsing logic beyond passing rule paths/keys.
- Reporter rendering logic.

---

## 8. Implementation Checklist for Step Agents

Before implementing any step plan:

- Read this document.
- Confirm the module and Java package names match §2.
- Use `common` records/interfaces for all cross-step artifacts.
- Do not redefine `Finding`, `FindingsDoc`, `ManifestFacts`, `Severity`, `ArtifactStore`, or `SignatureParser` in a step module.
- Keep analyzer-specific rule models in their analyzer module.
- Read/write artifacts by path/key; do not rely on stdout as a data channel.
- Use root dependency versions.
- Keep step CLIs compatible with §4.3.
