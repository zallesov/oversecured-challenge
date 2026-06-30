# Task 1 Report — Callback Context Propagator + Status-Emit Interceptor

## Status

DONE — all tests pass, compile is clean.

## Files Created

| File | Description |
|---|---|
| `orchestrator/src/main/java/…/workflow/CallbackContext.java` | Record: url, secret, runId; isPresent() |
| `orchestrator/src/main/java/…/workflow/CallbackContextPropagator.java` | ContextPropagator impl; ThreadLocal holder; static current() |
| `orchestrator/src/main/java/…/workflow/StatusEvent.java` | Wire-contract record + running/fromResult/failed factories |
| `orchestrator/src/main/java/…/workflow/StatusEmitter.java` | Interface (best-effort, must not throw) |
| `orchestrator/src/main/java/…/workflow/HttpStatusEmitter.java` | POST impl using java.net.http; 3 s timeout; swallows Throwable |
| `orchestrator/src/main/java/…/workflow/ActivityNodeIds.java` | nodeIdForActivityType() mapping (7 known types) |
| `orchestrator/src/main/java/…/workflow/StatusReporting.java` | runWithEmit() — testable core, no Temporal types |
| `orchestrator/src/main/java/…/workflow/StatusEmitInterceptor.java` | WorkerInterceptorBase + ActivityInboundCallsInterceptorBase |
| `orchestrator/src/test/java/…/ActivityNodeIdsTest.java` | 8 tests — all 7 known mappings + unknown passthrough |
| `orchestrator/src/test/java/…/StatusEventTest.java` | 4 tests — running, fromResult (COMPLETED + FAILED), failed factory |
| `orchestrator/src/test/java/…/StatusReportingTest.java` | 7 tests — present/absent ctx, body throws, emitter throws, unreachable URL |

## Files Modified

| File | Change |
|---|---|
| `orchestrator/src/main/java/…/cli/WorkerMain.java` | Register CallbackContextPropagator on WorkflowClient; register StatusEmitInterceptor on WorkerFactory |

## Test Command and Output

```
./gradlew :orchestrator:test
```

Output tail:
```
> Task :orchestrator:test

BUILD SUCCESSFUL in 6s
19 actionable tasks: 5 executed, 14 up-to-date
```

Test counts (from XML results):
- `ActivityNodeIdsTest`: 8 tests, 0 failures
- `StatusEventTest`: 4 tests, 0 failures
- `StatusReportingTest`: 7 tests, 0 failures
- Total suite: 53 tests, 0 failures, 0 errors

## Final Emitted JSON Shape

```json
{
  "runId": "run-abc123",
  "nodeId": "taint",
  "state": "RUNNING|COMPLETED|FAILED",
  "message": null,
  "occurredAt": "2026-06-30T12:00:00.123456Z",
  "metrics": {},
  "findingsKeys": [],
  "findingCount": 0,
  "severityCounts": {},
  "error": null
}
```

For COMPLETED with findings:
```json
{
  "runId": "run-abc123",
  "nodeId": "taint",
  "state": "COMPLETED",
  "message": "found 3 issues",
  "occurredAt": "2026-06-30T12:00:05Z",
  "metrics": {"durationMs": 4200},
  "findingsKeys": ["findings/taint-run-abc123.json"],
  "findingCount": 3,
  "severityCounts": {"ERROR": 2, "WARNING": 1},
  "error": null
}
```

For FAILED:
```json
{
  "runId": "run-abc123",
  "nodeId": "taint",
  "state": "FAILED",
  "message": "out of memory",
  "occurredAt": "2026-06-30T12:00:05Z",
  "metrics": {},
  "findingsKeys": [],
  "findingCount": 0,
  "severityCounts": {},
  "error": {"kind": "UNKNOWN", "message": "out of memory"}
}
```

## Three Temporal Header Key Names

1. `callbackUrl`
2. `callbackSecret`
3. `runId`

These are public constants on `CallbackContextPropagator`: `URL`, `SECRET`, `RUN_ID`.

## Deviations from Brief

1. **`runWithEmit` signature**: the brief evolved mid-description to add a `Function<Object,StepResult> extractor` parameter. The implementation uses `runWithEmit(ctx, runId, nodeId, clock, emitter, extractor, body)` — 7 parameters. Tests use `o -> (StepResult) o` as the extractor directly (no Temporal types needed in tests). The interceptor passes `o -> { Object r = ((ActivityOutput) o).getResult(); return r instanceof StepResult s ? s : null; }`.

2. **`StepResult.completed` factory**: the brief's test skeleton assumed a 6-arg overload. The actual `StepResult` has a 7-arg overload requiring an explicit `List<ArtifactRef>` artifacts parameter. Tests were adjusted to pass `List.<ArtifactRef>of()`.

No other deviations. Temporal 1.36.0 API matched the brief exactly for `ContextPropagator`, `WorkerInterceptorBase`, and `ActivityInboundCallsInterceptorBase`.

## Concerns

None. Implementation is complete, compile is clean, 53/53 tests pass.
