---
change_id: storage-ebpf-mvp
revision: 1
level: L3
execution_mode: DURABLE
route: DESIGN_FIRST
confirmation: CONFIRMED-AUTO
lifecycle: BLOCKED
confirmed_by: user implementation request and adb-root clarification
baseline: empty repository
---

# Android eBPF Storage Studio — MVP Specification

## Problem and goal

[User] Storage engineers need a Windows-native tool that controls an ADB-connected Android phone and uses eBPF on the phone to capture and analyze storage activity.

The MVP succeeds when a user can select an `adb root` capable phone, inspect its probe capabilities, deploy/start the collector, view block-I/O activity live, save a loss-aware session, and reopen it for analysis.

## Scope fence

- Included: Windows desktop GUI; ADB device discovery/root/capability checks; Android arm64 collector deployment; block issue/complete correlation; read/write, bytes, latency, queue depth, process, device and sector data; sequential/random classification; per-second throughput/IOPS/latency; NDJSON and CSV export; offline session reopening; optional UFS tracepoint detection.
- Excluded: modifying kernel/system images; production phone support without root; packet/network observability; automatic workload generation; Perfetto UI embedding; macOS/Linux desktop packaging.
- Forbidden: logging ADB credentials, user file contents, command payload buffers, or arbitrary kernel memory; silently claiming eBPF when a fallback backend is active.

## Sources, assumptions, and decisions

| ID | Kind | Statement | Provenance | Impact if wrong |
| --- | --- | --- | --- | --- |
| DEC-001 | Decision | Desktop uses pure Rust `eframe/egui`; no Node runtime. | [User], [External source] eframe native API | GUI build changes if Windows backend is incompatible. |
| DEC-002 | Decision | Android collector uses Aya and an eBPF ring buffer; Windows communicates only through ADB/stdout NDJSON. | [External source] Aya template/API | Collector build must be revised if Android libc/kernel compatibility differs. |
| DEC-003 | Decision | Block tracepoints are mandatory; UFS/vendor tracepoints are optional and capability-gated. | [Assumption] kernel event availability differs by device | Some devices provide block-only analysis. |
| DEC-004 | Decision | Repository name defaults to private `SeokMinKo/android-ebpf-studio`. | [User], reversible privacy-first default | User may later change visibility/name. |

## Functional requirements

| ID | Observable rule | Priority |
| --- | --- | --- |
| REQ-001 | List authorized ADB devices with serial, model, Android version and ABI. | Must |
| REQ-002 | Preflight must verify `adb root`, BPF syscall/filesystem, tracefs block events, and report BTF/UFS capabilities without hiding failures. | Must |
| REQ-003 | Start/stop must deploy and run the Android collector on the selected serial and stream structured events to Windows. | Must |
| REQ-004 | Correlate issue and completion by request identity and compute latency without producing a false match after timeout/reuse. | Must |
| REQ-005 | Live UI must show throughput, IOPS, p50/p95/p99 latency, queue depth and recent events, filterable by PID/process/read-write/device. | Must |
| REQ-006 | Classify adjacent block requests as sequential or random using device, direction, sector continuity and a configurable time window. | Must |
| REQ-007 | Persist a session as versioned NDJSON and export event/summary CSV; malformed lines are counted and reported. | Must |
| REQ-008 | Reopen a saved session and reproduce aggregate metrics without an attached device. | Must |
| REQ-009 | Detect UFS tracepoints and activate only supported probes; UI must label unavailable probes. | Should |
| REQ-010 | Include a deterministic simulator so desktop analysis can be tested without a phone. | Must |

## Non-functional requirements

| ID | Constraint | Verification |
| --- | --- | --- |
| NFR-001 | UI remains responsive while receiving at least 10,000 events/s; bounded channel and dropped-event counter prevent unbounded memory. | simulator soak test/manual profile |
| NFR-002 | Session schema is explicitly versioned and unknown fields remain forward-compatible. | serde tests |
| NFR-003 | Device commands bind to an explicitly selected, validated serial; no shell interpolation of user input. | unit tests/code inspection |
| NFR-004 | Windows x86_64 desktop and Rust tests compile in GitHub Actions; Android build job documents NDK/nightly prerequisites. | CI |

## Contracts and invariants

### CON-001 ADB target boundary

- Preconditions: serial comes from `adb devices -l`; state is `device`; preflight succeeded.
- Postcondition: every device-mutating command includes `-s <serial>`.
- Failure: command, exit status and bounded stderr are surfaced; capture does not enter Running state.
- Atomicity: failed deployment removes the staged temporary binary when possible.

### CON-002 Event correlation

- Issue inserts one pending request keyed by request ID plus device.
- Completion removes at most one matching pending request.
- Missing or expired issue produces an explicitly uncorrelated completion, never latency zero.
- Pending entries expire after a configured TTL and increment an expiration counter.

### INV-001 Session integrity

`events_seen = events_persisted + events_dropped + events_rejected` at session close, with every counter stored in the footer.

## Acceptance examples

- SCN-001: Given an authorized arm64 userdebug phone with block tracepoints, when Start is pressed, then the UI enters Running only after agent readiness and displays real block events.
- SCN-002: Given issue request `R` at 1 ms and completion `R` at 3.5 ms, when analyzed, then latency is 2.5 ms and queue depth returns to its prior value.
- SCN-003: Given sectors 100+8 then 108+8 on one device/direction inside the window, then the second request is Sequential; a jump to 4096 is Random.
- SCN-004: Given a session containing malformed NDJSON, reopening retains valid events and reports the exact rejected-line count.

BDD Discovery expansion: N/A — the user supplied an implementation goal and clarified the material privilege boundary; device-specific UFS fields remain capability-gated rather than inferred.

## Observability

### OBS-001 Capture lifecycle

Structured host diagnostics use bounded fields: `event`, `session_id`, `serial_hash`, `state.from`, `state.to`, `operation`, `duration_ms`, `outcome`, `error_code`, `dropped_events`. Raw serials are visible in the local UI but are not written to diagnostic logs by default. Collector stderr is bounded and never merged into the event stream.

### OBS-002 Collector health

Agent emits versioned `hello`, `capabilities`, periodic `health`, `event`, and final `footer` records. Health includes emitted and kernel/user-space drop counters.

## Risks and rollback

| Risk | Mitigation | Stop/rollback |
| --- | --- | --- |
| Android SELinux/verifier rejects dynamic BPF | preflight and verifier stderr; userdebug/root target; no policy modification | stop capture and retain diagnostic bundle |
| Kernel tracepoint layout differs | CO-RE/BTF where available; capability/profile selection; block-only baseline | disable incompatible probe, never guess fields |
| High-rate event loss | per-CPU ring buffer, bounded host queue, explicit counters | reduce probes/sampling and restart session |
| Windows build/API drift | pinned Cargo.lock, CI on windows-latest | revert dependency update |

## Verification and Definition of Done

- Protocol, correlation, classification, aggregation and malformed-input tests pass.
- Windows workspace check/test/format/clippy pass in CI.
- Simulator demonstrates the complete GUI/session path.
- Android collector build instructions and capability diagnostics are present; a real-phone run remains explicitly unverified until executed on the user's device.
- Every Must requirement has evidence or is reported as device-environment blocked; no critical/high gap is hidden.

## Revision log

| Revision | Reason | Confirmation |
| --- | --- | --- |
| 1 | Initial storage-focused scope after user confirmed `adb root` | CONFIRMED-AUTO |
