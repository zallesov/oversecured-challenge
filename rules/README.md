# `rules` — external detection rules (NOT hardcoded)

The abstract, external rule files that drive detection. This directory is the answer to the challenge requirement: *"The detection rules must not be hardcoded — they live in an external, abstract rules format."*

Part of the [Android Taint SAST Pipeline](../docs/superpowers/specs/2026-06-27-android-taint-sast-design.md).

## Files
| File | Drives | Vulnerability class |
|------|--------|---------------------|
| `webview.yaml` | step 4 `taint` | Intent/deeplink data → `WebView.loadUrl` (open redirect / XSS, CWE-601) — **the primary target class**. |
| `pathtraversal.yaml` | step 4 `taint` | Uri path segment → file open (path traversal, CWE-22) — second class on the **same** engine, proving rules are config not code. |
| `intent-redirect.yaml` | step 4 `taint` | `getParcelableExtra` nested Intent → `startActivity` (Intent redirection, CWE-927). |
| `file-theft.yaml` | step 4 `taint` | `ACTION_PICK` result `Intent.getData()` Uri → `FileUtils.copyToCache` (file theft, CWE-200). |
| `login-url-injection.yaml` | step 4 `taint` | deeplink `getQueryParameter("url")` → `LoginUtils.setLoginUrl` (untrusted endpoint override, CWE-601). |
| `credential-log-leak.yaml` | step 4 `taint` | credentials → `android.util.Log` (sensitive data in logcat, CWE-532). |
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
Drop a new YAML file here. The orchestrator runs every rule in this directory by default
(`start-analysis --rules all`, the default), so no code change is needed — that is the whole point.
The file's base name **is** the rule name: `rules/foo.yaml` → rule `foo` → findings key
`findings-foo.json`.

Select a subset with `--rules foo,bar` (comma/space separated). `misconfig` is reserved for the
manifest-misconfig analyzer (its own branch) and is excluded from the taint `all` set.

## Notes
Full schema and rationale in spec §5. The engine is policy-agnostic; all detection lives here.
