# `rules` — external detection rules (NOT hardcoded)

The abstract, external rule files that drive detection. This directory is the answer to the challenge requirement: *"The detection rules must not be hardcoded — they live in an external, abstract rules format."*

Part of the [Android Taint SAST Pipeline](../docs/superpowers/specs/2026-06-27-android-taint-sast-design.md).

## Files
| File | Drives | Vulnerability class |
|------|--------|---------------------|
| `webview.yaml` | step 4 `taint` | Intent/deeplink data → `WebView.loadUrl` (open redirect / XSS, CWE-601) — **the primary target class**. |
| `pathtraversal.yaml` | step 4 `taint` | Uri path segment → file open (path traversal, CWE-22) — second class on the **same** engine, proving rules are config not code. |
| `misconfig.yaml` | step 5 `manifest-misconfig` | Manifest misconfigurations (exported without permission, provider grantUriPermissions, weak host validation). |

## Format (taint rules)
FlowDroid/Soot-style method signatures grouped per vulnerability class:

```yaml
version: 1
rules:
  - id: ANDROID_WEBVIEW_INTENT_LOADURL
    vulnerability_class: webview-open-redirect
    severity: error
    cwe: CWE-601
    message: "Untrusted Intent/deeplink data flows into WebView.loadUrl"
    manifest_conditions:
      reachable_from_exported: true
    sources:
      - signature: "android.content.Intent: java.lang.String getStringExtra(java.lang.String)"
    sinks:
      - signature: "android.webkit.WebView: void loadUrl(java.lang.String)"
        tainted_args: [0]
    sanitizers: []
```

Signature grammar: `<fully.qualified.Class: ReturnType methodName(ParamType,...)>` (inner classes use `$`).

## Adding a vulnerability class
Drop a new YAML file here and add it to the orchestrator `analysisPlan`. No engine code changes — that is the whole point.

## Notes
Full schema and rationale in spec §5. The engine is policy-agnostic; all detection lives here.
