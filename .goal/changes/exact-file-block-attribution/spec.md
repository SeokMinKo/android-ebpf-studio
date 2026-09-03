---
change_id: exact-file-block-attribution
revision: 1
level: L3
execution_mode: DURABLE
route: DESIGN_FIRST
confirmation: CONFIRMED-AUTO
lifecycle: CONFIRMED
confirmed_by: user "Go" on 2026-09-03
baseline: 3a70f1b
---

# Exact file-to-block attribution

## Goal

On rooted Android userdebug devices, attribute each supported block request to zero, one, or many stable file identities and show the best available path snapshot. Direct kernel identity propagation is `Exact`; the existing syscall/time/task heuristic remains a lower-confidence fallback.

## Scope

- Typed BTF probe capability and attach reporting.
- Stable file identity capture above the block layer.
- Bounded file-origin propagation through bio/request identities.
- Exact multi-origin nodes/edges in the transaction graph.
- Backward-compatible NDJSON and current tracepoint fallback.
- Unit/build/static verification here; verifier and workload validation on a real target phone are a separate gate.

Out of scope: bypassing SELinux/kernel policy, reconstructing paths by unbounded dentry walking in the block hot path, claiming an original write syscall for asynchronous writeback without a direct causation token, and inventing a user-file path for filesystem metadata/journal/GC I/O.

## Functional requirements

| ID | Requirement |
| --- | --- |
| REQ-001 | Capability output MUST distinguish BTF presence, typed-probe attach success, selected probes, and fallback/unavailable reasons. |
| REQ-002 | A supported upper-layer probe MUST capture filesystem device and inode from `struct file`/`struct inode`; inode generation and mount ID are optional when safely available. |
| REQ-003 | A supported bio submission path MUST bind a bounded set of file origins to the bio identity, and the block path MUST transfer all known origins to the request identity. |
| REQ-004 | One request MAY contain multiple file origins; no origin may be silently collapsed to a single winner. |
| REQ-005 | Directly propagated origins MUST become `Exact` graph edges. Time/task/size matching MUST remain `Probable` or `ProbableAsync` and MUST NOT override exact origins. |
| REQ-006 | Path is a timestamped snapshot joined to `FileIdentity`; missing/renamed/deleted paths MUST NOT invalidate the identity. |
| REQ-007 | Existing tracepoint-only collection and schema records MUST remain readable and operational when typed probes fail to attach. |
| REQ-008 | Overflow, missing origin, expired/reused key, and attach failure MUST be observable rather than fabricated as successful attribution. |

## Non-functional requirements

| ID | Requirement |
| --- | --- |
| NFR-001 | eBPF loops and origin fan-in MUST be statically bounded; maps MUST have fixed capacities and stale entries MUST be removed at terminal lifecycle points where observable. |
| NFR-002 | Raw kernel pointers MUST NOT cross the kernel/userspace boundary; exported correlation keys MUST be session-salted opaque values. |
| NFR-003 | Kernel structure access MUST be BTF/CO-RE based or capability-gated; vendor structure offsets MUST NOT be hardcoded. |
| NFR-004 | Failure of optional exact attribution MUST not prevent mandatory block capture. |

## Invariants

- INV-001: inode identity is not a path; `PathSnapshot` remains separate.
- INV-002: `Exact` requires a directly observed kernel identity chain, never temporal coincidence alone.
- INV-003: request origin cardinality is 0..N and all retained origins are independently queryable.
- INV-004: metadata/journal/GC/swap origins are not mislabeled as user files.
- INV-005: raw pointer reuse is bounded by observed lifecycle and never exported directly.

## BDD acceptance examples

### Exact single-file request

Given a supported typed probe observes file identity F and its bio is queued into request R, when R completes, then the graph for R contains F with an `Exact` incoming origin edge and any matching syscall path is only used as F's snapshot/fallback context.

### Exact merged request

Given bios from identities F1 and F2 are merged into R, when R completes, then both F1 and F2 appear as exact origins and neither is discarded.

### Unsupported kernel fallback

Given BTF or required attach points are unavailable, when capture starts, then mandatory block tracepoints still run, capability output names exact attribution as unavailable, and heuristic correlation never reports `Exact`.

### Buffered writeback boundary

Given a write syscall returns before writeback creates block I/O and no direct page/inode-to-bio chain is observed, when the request completes, then the syscall-to-request relationship is at most `ProbableAsync`.

## Verification contract

- Protocol RED/GREEN tests cover exact precedence, multi-origin, and backward fallback.
- Agent/eBPF layout tests cover event decoding and pointer redaction.
- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` are required when the pinned Rust toolchain is available.
- Target-phone acceptance requires: preflight output, verifier/attach log, direct read/write workload, buffered writeback workload, and a merged-origin fixture or workload. Host-only work cannot satisfy this gate.
