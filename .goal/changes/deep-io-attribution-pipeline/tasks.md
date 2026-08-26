# Task DAG — Deep I/O Attribution & Pipeline

- Artifact: `tasks@1`
- Status: `CONFIRMED`
- Derived from: `spec@1`, `design@1`
- Execution: one stream; tasks run in ID order.

## TSK-001 — Protocol v4 and graph value types

- Spec: REQ-010~014, REQ-020~027, REQ-056, NFR-005/008, INV-001/002/006/007
- Depends: none
- Paths: `crates/protocol/**`, `crates/ebpf-types/**`
- First RED: v4 round-trip/multi-origin compatibility tests cannot compile because types do not exist.
- Observability: diagnostic and health schemas are included but sinks are later tasks.
- DoD: typed identity/node/edge/evidence/health contracts and v1~v3 compatibility tests.

## TSK-002 — Graph correlation, time accounting and RCA

- Spec: REQ-020~027, REQ-040~044, REQ-055, INV-002~006
- Depends: TSK-001
- Paths: `crates/protocol/src/lib.rs`, `crates/protocol/tests/**`
- First RED: split/merge, ambiguous file candidate, exclusive and critical-path tests fail.
- Observability: correlation outcomes expose counters/reason codes.
- DoD: deterministic DAG builder, no-forced-attribution, critical path and cohort RCA.

## TSK-003 — Agent/eBPF capture and capability profiles

- Spec: REQ-001~004, REQ-011/012, REQ-030~036, REQ-060/063~066, NFR-001/004
- Depends: TSK-001
- Paths: `crates/android-agent/**`, `crates/android-ebpf/**`, `crates/ebpf-types/**`
- First RED: trace fixtures cannot produce file identity/UFS/SCSI/FS observations or reserve counters.
- Observability: agent JSONL lifecycle/probe/decode/health events.
- DoD: runtime optional layout adapters, file stat snapshot, bounded counters, unavailable semantics.

## TSK-004 — Host logging, session integrity and diagnostic bundle

- Spec: REQ-060~069, NFR-002~004/007
- Depends: TSK-001
- Paths: `crates/desktop/src/capture.rs`, `session.rs`, new diagnostics module/tests
- First RED: continuous stderr/rotation/redaction/integrity tests fail.
- Observability: this task implements the host sink itself.
- DoD: dual-stream drain, rotating log files, structured UI records and bundle export.

## TSK-005 — Interactive graph, file filters, FS breakdown and RCA UI

- Spec: REQ-040~055
- Depends: TSK-002, TSK-004
- Paths: `crates/desktop/src/app.rs`, `simulator.rs`, desktop tests
- First RED: simulator graph lacks multi-origin/filter/RCA fields.
- Observability: UI links diagnostic correlation IDs to transaction selection.
- DoD: Summary/Pipeline/Explorer/File/Diagnostics share selection and filters.

## TSK-006 — Documentation and conformance

- Spec: all Must IDs
- Depends: TSK-003, TSK-004, TSK-005
- Paths: `README.md`, `docs/**`, `.goal/changes/deep-io-attribution-pipeline/**`
- First check: documented protocol/runbook diverges from delivered types and commands.
- DoD: exact checks recorded, device-unverified items explicit, no critical/high gap hidden.

## Execution reconciliation — 2026-08-26

The working patch currently spans TSK-001 through TSK-006 because an integrated implementation was produced before the sequential leases were reconciled. This is recorded as a workflow mismatch, not as task completion. No task is `done`: Rust compilation and behavior suites are unavailable in the current environment, and device-only requirements remain blocked. Resume by compiling the whole patch, fixing all errors, then close each task against its original DoD and exact evidence in dependency order.
