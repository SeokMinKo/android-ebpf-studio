# Design

## Domain vision and language

The core capability is trustworthy storage-observation analysis. `Block request` is generic block-layer work; `File syscall` is a process-facing read/write observation and does not imply that the same bytes reached a specific block request. `Busy` means at least one observed block request is active. `Logging` is the observed event span.

## Decisions

- DEC-101: Keep classification and aggregation in the platform-neutral protocol crate so live, offline, CSV, and simulator paths share one policy.
- DEC-102: Extend the request correlator with optional insert state. This is a smaller and safer boundary than a general stage graph while covering the portable Android block pipeline.
- DEC-103: Resolve syscall FD links in the root Android agent instead of dereferencing kernel path structures. This works without vendor BTF layouts, but is explicitly `Attributed` rather than exact.
- DEC-104: Store bounded completed I/O samples for Explorer rendering and maintain unbounded aggregate counters/intervals for Summary.
- DEC-105: Use egui_plot scatter/line series grouped by a selectable category. Missing Y values are skipped.

## Data flow

`tracepoint -> KernelEvent -> agent translation/path resolution -> WireRecord -> AnalysisEngine -> CompletedIo/summary/chart -> GUI/CSV`

## Test strategy

Inside-out: first prove pure classification/timing/utilization, then protocol translation and simulator, then compile the GUI and collector boundaries. No test doubles are needed for pure rules; `/proc` resolution remains a small adapter with failure-safe behavior.

## Observability

- OBS-101: capability record advertises insert and file syscall support.
- OBS-102: every file event includes confidence; missing path is visible.
- OBS-103: Summary exposes uncorrelated completions and observed-time semantics.

