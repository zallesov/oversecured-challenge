# `benchmark` — validation & ground truth

Test fixtures and scoring that prove precision/recall and the false-positive-rate → 0 goal.

Part of the [Android Taint SAST Pipeline](../docs/superpowers/specs/2026-06-27-android-taint-sast-design.md).

## Contents
- **DroidBench harness** — runs the pipeline over selected [DroidBench](https://github.com/secure-software-engineering/DroidBench) cases and scores results against ground truth. DroidBench encodes expected leaks via a JavaDoc `@number_of_leaks` tag plus `// source` / `// sink, leak` comments; the harness parses these, tabulates **TP / FP / FN**, and reports **precision / recall / F1**.
  - In scope: `GeneralJava`, `Lifecycle` / `Callbacks` (with entry-point model), simple `FieldAndObjectSensitivity`, ICC/WebView-relevant cases.
  - Out of scope (documented): `Reflection(_ICC)`, `ImplicitFlows`, full `InterComponent/InterAppCommunication`, `DynamicLoading`, `Native`, `Threading`, `EmulatorDetection`.
- **OVAA fixture** — [oversecured/ovaa](https://github.com/oversecured/ovaa). No prebuilt release; build with `./gradlew assembleDebug`. End-to-end expectation: exactly **2** taint findings (deeplink→`loadUrl`, Uri→`ParcelFileDescriptor.open`) and **0** false positives.
- **Opengrep oracle (optional)** — runs a Semgrep-style ruleset side-by-side as an independent baseline to show our detections match a battle-tested tool. Not part of detection; comparison only.

## Usage (illustrative)
```
benchmark droidbench --categories GeneralJava,Lifecycle --out score.json
benchmark ovaa --apk ovaa.apk
benchmark oracle --apk ovaa.apk            # optional Opengrep comparison
```

## Why it matters
The challenge requires the false-positive rate be driven to ~0. The DroidBench score and the OVAA end-to-end expectation are the evidence. Reachability filtering (taint step + manifest facts) is what keeps FP low; this harness quantifies it.

## Notes
See spec §8 (validation) and §9 (reference-tool positioning).
