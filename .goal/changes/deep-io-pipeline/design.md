# Design

## Model

`PipelineObservation` is the wire-level fact. `PipelineSpan` is a normalized interval. `IoPipeline` is a view for one completed block request.

- Layers: Syscall, VFS, Filesystem, Block, SCSI, UFS, UIC Context.
- Confidence: Exact, Probable, ContextOnly.
- Phases: Begin, End, Instant, CompleteSpan.
- Correlation: request/tag/thread ID plus optional LBA and byte length.

Kernel Space is rendered as a visual grouping around VFS through UFS, not counted as a stage.

## Accounting

1. Clip additive spans to the pipeline request window.
2. Merge overlapping/nested intervals.
3. `accounted_ns` is the union duration.
4. `unaccounted_ns` saturates at `total_ns - accounted_ns`.
5. Context-only markers are displayed but excluded.

## Correlation

1. Exact correlation ID match.
2. Otherwise overlap plus equal LBA/bytes when both are available.
3. Otherwise overlap plus same pid/tid for upper layers.
4. Do not attach an ambiguous observation; expose it in global diagnostics.

## UI

Pipeline page contains request filters/list, a zoomable time-axis waterfall, an accounting header, a confidence legend and missing-capability callouts. Clicking a request or bar updates the detail panel.

## Error and observability

### OBS-001: pipeline correlation diagnostics
- Spec/Task IDs: REQ-003, REQ-004, NFR-003
- Diagnostic question: Was a layer absent, unsupported, dropped, or merely uncorrelated?
- Signal: session capabilities plus pipeline confidence/unaccounted fields.
- Correlation: request ID, optional stage correlation ID, sector and bytes.
- Safe context: bounded tracepoint name, pid/tid, numeric timing.
- Redaction: no payload content; file paths retain existing policy.
- Cardinality: UI retains the existing bounded sample window.
- Tests: protocol pipeline tests and simulator acceptance.

## Alternatives rejected

- Naively summing stage durations: double-counts nesting.
- Showing unsupported layers as 0 ms: falsely implies measurement.
- Calling UIC management events per-request latency: unsupported causal claim.
- Hard-coded vendor tracepoint offsets: unsafe across Android kernels.
