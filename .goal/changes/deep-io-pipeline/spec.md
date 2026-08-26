# Deep I/O Pipeline — Specification

- Canonical path: `.goal/changes/deep-io-pipeline/spec.md`
- Baseline: `7e791b5cdec1e52f0f3858cc27e47319af50b17c`
- Route: `L3 / DURABLE / DESIGN_FIRST`
- Confirmation: `CONFIRMED-AUTO`
- Lifecycle: `CONFIRMED`
- Confirmation basis: user explicitly requested implementation; repository changes are reversible.

## Goal

Let a Windows operator inspect Android storage I/O as a request-oriented timeline from syscall through VFS/filesystem, block, SCSI and UFS, while clearly separating measured, inferred, contextual and unavailable data.

## Scope

- ADDED: versioned pipeline stage events and capability reporting.
- ADDED: request pipeline construction, overlap-safe accounted/unaccounted time and confidence.
- ADDED: interactive Pipeline page with request selection and waterfall.
- ADDED: deterministic full-pipeline simulator data.
- MODIFIED: Android probe inventory for SCSI, UFS, F2FS/ext4 and VFS prerequisites.
- UNCHANGED: existing Summary, Explorer, Events, Files, classification and NDJSON loading.
- DEFERRED: exact page-cache/writeback DAG, UFS controller/media internal time, per-command UIC latency, arbitrary vendor-kernel symbol probing.

## Requirements

- REQ-001: The protocol shall represent Syscall, VFS, Filesystem, Block, SCSI, UFS and UIC-context observations with phase, interval, source and confidence.
- REQ-002: Pipeline analysis shall never double-count overlapping measured intervals and shall report non-negative Unaccounted time.
- REQ-003: A completed block request shall expose a request-oriented pipeline; exact ID matches outrank probable time/LBA/size matches.
- REQ-004: Probe output shall inventory available SCSI, UFS, F2FS/ext4 events and VFS/BTF prerequisites without treating absence as zero latency.
- REQ-005: The desktop shall provide an interactive waterfall with request selection, zoom/pan, stage detail, confidence legend and capability gaps.
- REQ-006: The simulator shall produce all pipeline layers so the UI can be evaluated without a rooted phone.
- REQ-007: Starting capture shall auto-discover the bundled agent/object and create a timestamped NDJSON path without three file-picker prompts.
- NFR-001: Schema evolution shall preserve loading of schema-v2 sessions via serde defaults and tagged variants.
- NFR-002: Context-only UIC observations shall not contribute to additive latency.
- NFR-003: Correlation quality and unavailable layers shall be visible rather than silently fabricated.

## Contracts and invariants

- CON-001: A span requires `end_ts_ns >= start_ts_ns`; invalid spans are rejected from accounting.
- CON-002: `accounted_ns <= total_ns` and `unaccounted_ns = total_ns - accounted_ns`.
- INV-001: Kernel Space is a group boundary, not a sibling latency stage.
- INV-002: `ContextOnly` observations are rendered but excluded from additive accounting.
- INV-003: An unavailable capability is distinct from a measured duration of zero.

## Acceptance scenarios

- SCN-001: Given overlapping FS and Block spans, when a pipeline is built, then accounted time uses their union and never exceeds the request duration.
- SCN-002: Given a UIC context marker, when totals are calculated, then it appears in detail but does not reduce Unaccounted time.
- SCN-003: Given simulator capture, when Pipeline is opened, then every requested layer is visible with honest confidence labels.
- SCN-004: Given a device without UFS/F2FS tracepoints, when preflight runs, then capture remains usable and missing layers are listed as unavailable.
- SCN-005: Given the release ZIP is extracted intact, when capture starts, then sibling agent/object files are deployed and output is created below `%LOCALAPPDATA%/AndroidEbpfStudio/sessions`.

## Definition of done

- Protocol and analysis tests cover REQ-001..003 and compatibility.
- Desktop GUI compiles and simulator demonstrates the waterfall.
- Agent probe inventory tests cover SCSI/UFS/FS discovery classification.
- Workspace format, clippy and tests pass; Android eBPF build is attempted and evidence recorded.
- README and device runbook explain capabilities and limitations.

## Stop conditions

Stop and report rather than inventing data if a target kernel exposes neither stable tracepoints nor attachable symbols for a requested layer, or if device-only verification cannot run in the available environment.
