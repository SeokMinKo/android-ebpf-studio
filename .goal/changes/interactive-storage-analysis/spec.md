# Interactive storage analysis delta

- Level/route: `L3 / DURABLE / DESIGN_FIRST`
- Baseline: GitHub `main` at `1f1ab8f`
- Lifecycle: `CONFIRMED-EXPLICIT`
- Confirmation basis: the user explicitly requested implementation and named the classification rules and UI capabilities.

## Goal

Give a Windows operator an interactive, evidence-labelled view of Android storage I/O: request origin where observable, block pipeline latency, freely selectable chart dimensions, category summaries, and capture utilization.

## ADDED

- REQ-101: Every completed block I/O is classified independently by direction (`Read`, `Write`, `Other`), access pattern (`Sequential`, `Random`, `Unknown`), and size (`Large`, `Small`).
- RULE-101: `Sequential` means the previous request in the same device and direction stream ends exactly at the current start sector. The first request is `Unknown`; every non-contiguous subsequent request is `Random`.
- RULE-102: `Large` means `bytes >= 32 KiB`; `Small` means `bytes < 32 KiB`.
- REQ-102: The analyzer exposes block pipeline stages `insert -> issue -> complete` when the target exposes `block_rq_insert`; missing stages remain unavailable, never zero-filled.
- REQ-103: The Android collector emits file syscall events for supported read/write syscall tracepoints, and userspace resolves `/proc/<pid>/fd/<fd>` immediately. The result carries an attribution confidence and must not be presented as exact block-to-file causality.
- REQ-104: Explorer lets the operator select X axis, Y axis, and grouping category at runtime; plot pan/zoom/legend remain interactive.
- REQ-105: Summary reports global logging, busy, and idle time and grouped count, bytes, average chunk, and latency percentiles.
- REQ-106: Simulator exercises read/write, sequential/random, small/large, insert/issue/complete, and file events without a phone.
- REQ-107: CSV and NDJSON persist the extended fields while the reader continues accepting protocol-v1 records.

## MODIFIED

- The previous sequential time window no longer participates in classification.
- Block latency is split into queue (`insert -> issue`) and device (`issue -> complete`) where insert exists; total is earliest observed block stage through completion.

## UNCHANGED

- ADB selected-serial discipline, root preflight, bounded host channel, loss/rejection accounting, and offline session loading.
- Generic block tracepoints remain the mandatory portable capture boundary.

## Semantics and invariants

- INV-101: `logging_ns = busy_ns + idle_ns` over the analyzer's observed timestamp span.
- INV-102: Busy time is the union of request intervals, so overlapping requests are not double-counted.
- INV-103: A missing stage or unresolved path is represented as `None`/`Unknown`, not numeric zero or a fabricated path.
- INV-104: Read and Write have separate sequential history.

## Acceptance scenarios

- SCN-101: 4 KiB read at sector 100 followed by read at 108 -> first Unknown, second Sequential; a write at 108 remains Unknown in its own stream.
- SCN-102: 32767-byte request -> Small; 32768-byte request -> Large.
- SCN-103: intervals [1, 5] ms and [3, 8] ms -> logging 7 ms, busy 7 ms, idle 0 ms.
- SCN-104: insert at 1 ms, issue at 3 ms, complete at 8 ms -> queue 2 ms, device 5 ms, total 7 ms.
- SCN-105: changing X/Y/group selectors changes the plotted projection without restarting capture.

## Contracts

- CON-101 analyzer ingest: monotonic kernel timestamps are accepted out of arrival order; negative durations are unavailable and counted as uncorrelated rather than underflowed.
- CON-102 file attribution: path resolution is bounded to 4096 bytes and tagged `Attributed`; permission/process-exit/FD-reuse failures return `Unknown`.
- CON-103 chart projection: unsupported metric values are omitted from that series, not coerced to zero.

## Non-goals / deferred

- Exact correlation from buffered filesystem writes to later writeback block requests.
- Vendor-independent UFS command stage correlation; discovered UFS events remain capability metadata.
- Kernel or SELinux policy modification.

## Definition of done

- Protocol unit tests cover boundary classifications, block stage timing, interval-union utilization, summaries, and v1 compatibility.
- Workspace fmt/clippy/tests, Windows GUI check, eBPF build, and Android arm64 agent build pass where the environment supports them.
- README/protocol/runbook document accuracy labels and unavailable-stage behavior.

