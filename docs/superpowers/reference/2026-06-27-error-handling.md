# Error Handling Conventions

**Date:** 2026-06-27
**Status:** Required reference for implementation plans
**Audience:** agents and developers implementing individual Android Taint SAST pipeline modules
**Related:** [Shared Contracts and Naming Conventions](2026-06-27-shared-contracts-and-conventions.md) · [Logging](2026-06-27-logging.md)

This document is the source of truth for how every pipeline module raises, classifies, translates, and reports errors. It is designed to fit the pipeline's architecture: independently runnable steps, artifact-per-step communication, and Temporal-driven retries.

---

## 1. Goals

- One error model that maps cleanly to **both** CLI exit codes and Temporal retry policy.
- A failure is classified once as **retryable** or **not**, at the place that knows.
- Deep code throws raw; **boundaries translate**; the **outermost boundary** reports.
- Partial, recoverable problems do not abort a step — they are accumulated and surfaced.
- No log-and-rethrow; an error is logged exactly once (see [Logging](2026-06-27-logging.md) §3).

---

## 2. Exception hierarchy

### 2.1 Shared base (in `common`)

```java
package com.oversecured.sast.common;

/** Failure classification that drives CLI exit codes and Temporal retry policy. */
public enum FailureKind {
    /** Bad/corrupt input, invalid rule, unsupported artifact — retrying will not help. */
    PERMANENT,
    /** IO, resource exhaustion, transient environment fault — retrying may succeed. */
    TRANSIENT
}
```

```java
package com.oversecured.sast.common;

/** Base for all pipeline step failures; carries a {@link FailureKind} for the boundary to act on. */
public class PipelineException extends RuntimeException {
    private final FailureKind kind;

    public PipelineException(FailureKind kind, String message) {
        super(message);
        this.kind = kind;
    }

    public PipelineException(FailureKind kind, String message, Throwable cause) {
        super(message, cause);
        this.kind = kind;
    }

    public FailureKind kind() {
        return kind;
    }
}
```

Per shared-conventions §3.1, `PipelineException`, `FailureKind`, and `Diagnostics` (§4) are legitimate cross-step `common` types: every step and the orchestrator exchange them.

### 2.2 Per-module domain exception

Each module defines **one** exception extending `PipelineException`:

```java
public class DecompilerException extends PipelineException {
    public DecompilerException(FailureKind kind, String message) { super(kind, message); }
    public DecompilerException(FailureKind kind, String message, Throwable cause) { super(kind, message, cause); }
}
```

Examples: `DecompilerException`, `ParserException`, `ManifestFactsException`, `TaintException`, `MisconfigException`, `ReporterException`. The module throws **only** its own type past its boundary.

---

## 3. Boundary translation

Three rules, mirroring the logging altitudes:

1. **Deep code throws raw.** Helpers, libraries (jadx, JavaParser, Jackson), and JDK IO throw whatever they throw (`IOException`, `RuntimeException`, …). They do not wrap, do not classify, do not log.
2. **The service boundary translates.** The module's public entry method catches raw throwables and wraps them in its domain exception with an explicit `FailureKind` and a human-readable message + cause. This is the only place that *decides* PERMANENT vs TRANSIENT.
3. **The outermost boundary reports.** The CLI `call()` / Temporal activity catches the domain exception, logs it **once** as ❌ (logging §5), and maps `FailureKind` to the outcome (§5, §6). Nothing below it logs the failure.

**Classification guide:**

| Cause | Kind |
|---|---|
| missing/empty/corrupt input, unparseable rule YAML, unsupported APK, "no usable output produced" | PERMANENT |
| `IOException` writing output, out-of-memory, temp-dir/resource failure, network (S3) | TRANSIENT |

When unsure, default to **PERMANENT** (fail fast, don't retry a deterministic failure).

---

## 4. Fail-soft accumulation (partial, recoverable problems)

Some steps must tolerate per-item failures rather than aborting (spec §6.1: the parser is fail-soft over decompiled source; jadx is best-effort). For these, collect per-item problems instead of throwing:

```java
package com.oversecured.sast.common;

import java.util.ArrayList;
import java.util.List;

/** Accumulates per-item, recoverable problems during a fail-soft step. */
public final class Diagnostics {
    public record Item(String where, String detail) {}

    private final List<Item> items = new ArrayList<>();

    public void add(String where, String detail) { items.add(new Item(where, detail)); }
    public List<Item> items() { return List.copyOf(items); }
    public boolean isEmpty() { return items.isEmpty(); }
    public int count() { return items.size(); }
}
```

Usage contract:

- A fail-soft boundary catches a per-item failure, records it in `Diagnostics`, and **continues**.
- After the loop, it logs **one** aggregated ⚠️ WARN line with `diagnostics.count()` (not one line per item).
- It throws its domain exception (`PERMANENT`) **only** when the step produced **no usable output at all** (e.g. zero files parsed, zero `.java` decompiled).
- When relevant downstream, the diagnostics summary may be carried in the output artifact's `notes`/metadata so the reporter can surface degraded coverage.

Steps that are all-or-nothing (e.g. `manifest-facts` parsing a single XML) do not need `Diagnostics` — they throw `PERMANENT` on failure.

---

## 5. CLI mapping (standalone runs)

The CLI `call()` is an outermost boundary:

| Outcome | Exit code | Log |
|---|---|---|
| success | `0` | ✅ INFO + one stdout summary line |
| `PipelineException(PERMANENT)` | `2` | ❌ ERROR (once) |
| `PipelineException(TRANSIENT)` | `1` | ❌ ERROR (once) |
| picocli usage error (missing/invalid option) | picocli default (`2`) | picocli usage message |

Errors are reported via the picocli command's error writer (`spec.commandLine().getErr()`), not raw `System.err`, so they are testable and consistent with the logging facade.

---

## 6. Orchestrator mapping (Temporal)

The Temporal activity implementation is the other outermost boundary. It calls the module's library API and translates `FailureKind` to retry policy:

- `PERMANENT` → wrap/mark as **non-retryable** (`ApplicationFailure.newNonRetryableFailure` or non-retryable type in `RetryOptions`). The workflow fails fast for this branch.
- `TRANSIENT` → **retryable**; Temporal applies the configured backoff and max attempts.

Because steps are idempotent (artifact-per-step), retrying a TRANSIENT failure is safe and free. The orchestrator never inspects exception messages for control flow — only `FailureKind`.

---

## 7. Implementation checklist for step agents

- Add nothing new to `common` except the three shared types here (`PipelineException`, `FailureKind`, `Diagnostics`) — defined once, imported everywhere.
- Define exactly one module domain exception extending `PipelineException`.
- Deep code throws raw; the service boundary wraps + classifies; the outermost boundary logs once + maps to exit code / retry policy.
- Classify every thrown failure as PERMANENT or TRANSIENT; default PERMANENT when unsure.
- Use `Diagnostics` for fail-soft steps; throw PERMANENT only when there is no usable output.
- No log-and-rethrow (see [Logging](2026-06-27-logging.md) §3).
