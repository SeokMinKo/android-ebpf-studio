# Scheduler I/O wait checkpoint — Goal remains active

2026-09-07. This is an implemented analysis/acquisition slice, not uPAS parity or final Release installation.

## Meaning and placement

Explore preset index 27, **Scheduler I/O wait over time**, plots scheduler accounting timestamp (ms from the common source origin) against task I/O wait delay (us). The existing right **Graph summary → Summary** contains that same cohort's exact nearest-rank percentiles, histogram, CDF/rank and exports. The central virtualized table follows the selected cohort. Clicking one point, selecting a rectangle, clearing, and applying/restoring a scheduler cohort are separate from block request identity selection. Applied scheduler cohorts stay local to this graph; they do not create a fabricated block-request filter.

uPAS `UpasAnalyzer.py`8120-8153 was executed through its actual AST against 200 equivalent fixture records. Its `delay / 1000` agrees for every point. uPAS displays seconds and logarithmic Y; Studio displays milliseconds and linear Y so measured zero remains visible. `Parser_SCHED_IOWait`1188-1236 uses the placeholder dispatch pattern `aaaddd`; enabled end-to-end uPAS scheduler acquisition is not inferred from that parser's existence.

## Acquisition, protocol and storage

- Protocol schema **8** adds `SchedulerIoWait { ts_ns, delay_ns, tid, pid: Option, comm, cpu: Option, source }`. Legacy sessions remain readable. No KernelEvent/eBPF object ABI change in this slice.
- Perfetto config requests `sched/sched_stat_iowait`. The decoder reads `GenericFtraceEvent` field 327, event name, delay and payload task `pid` (Linux task ID/TID), task comm and bundle observer CPU. It does not substitute the emitting event PID or invent a TGID. CPU 0 and measured zero delay remain valid. Missing/negative delay, invalid task identity and unsupported clocks never become zero samples.
- Sort scheduler packets by actual timestamp across CPUs. A malformed scheduler payload records a quality error while subsequent block and scheduler records in that bundle remain recoverable; regression test first failed, then passed after isolating the optional parser failure.
- Live/recovery projection, sequence/footer event counts, raw event CSV, NDJSON load and original-window reanalysis preserve scheduler events. They do not increase completed block I/O, payload, request latency or block busy intervals.
- Retain at most 100,000 scheduler samples with explicit dropped-detail counts (same bounded chunk eviction policy as request details). Full-session origin survives eviction. Selected-window replay rejects more than 100,000 scheduler samples, preserving the previous view, rather than silently dropping old selected samples.
- Waiting-task comm substring, TID, known PID, accounting time and observer CPU filters apply. Unknown PID never matches a specific PID. Device/operation/size/path/confidence/access/layer/block request-selection filters have no measured scheduler identity; the graph gives an explicit empty result and a **Clear block-only filters** action. Capture PID filtering remains separate. Scheduler-only sessions expose analysis filters.

Primary field definitions inspected:

- [Perfetto generic ftrace schema](https://github.com/google/perfetto/blob/main/protos/perfetto/trace/ftrace/generic.proto)
- [Perfetto ftrace event field registry](https://github.com/google/perfetto/blob/main/protos/perfetto/trace/ftrace/ftrace_event.proto)
- [Linux scheduler tracepoints](https://github.com/torvalds/linux/blob/master/include/trace/events/sched.h)

## Verification and evidence

Artifacts are under the task root's `outputs/graph-summary-validation/` (outside the Git worktree).

- `scheduler-verification.json`: independent Python percentile/bin/count and CSV checks; actual uPAS AST comparison. Native cases: 200-event full cohort (P50 9us/P95 18us), single zero-delay point, 95-event half-window region, missing-source empty state, incompatible block filter empty state, scheduler-only source, Process input/change/Clear (100→0→200), PID input/change/Clear (100→0→200), and large source.
- `scheduler-large.json/png`: 100,005 original events, 90,005 retained and 10,000 explicitly excluded, only 4,738 display points; Summary/CSV retain all 90,005. Original-window regression recovers the earliest six evicted events and rejects an oversized selected window.
- `scheduler-all.png`, `scheduler-large.png` visually reviewed: right Summary, visible percentile values/histogram, scrollable details and explicit retention coverage. `scheduler-existing-lba.png` confirms existing real 184-I/O LBA distributions/repeated-address counts still render.
- Added UI regressions for scheduler-only filters/common origin, populated/empty rendering, filter/selection/CSV population consistency, and detaching previous request-summary work on graph switch. The last test first failed with an unconsumed receiver; the fix eliminates native QA hangs after switching from a request graph. One initial native access violation did not recur in the subsequent native matrix; no definitive cause for that isolated exit is claimed.
- Common histogram counting now uses binary searches at sorted displayed bin boundaries, O(bins × log(samples)). Independent 100,000-value constant/tied/wide-magnitude interval counts agree. In single debug native runs, large-graph UI median improved 6.979→3.077ms. Startup-inclusive P95 was 91.836→105.890ms; this is **not** evidence of improved startup/P95 or final before/after performance acceptance.
- All Windows-compatible desktop/protocol/types all-target tests passed: **181 passed, 7 environment/manual tests ignored**, across 31 suites. Consolidated counts live in `scheduler-build-checkpoint.json` and `scheduler-tests.log`. Clippy with `-D warnings`, formatting and diff checks passed.
- Android agent all-target cross-check/Clippy and schema8 Release build passed using NDK r29 API35. Agent SHA256 `2693833306198f9400d2952fd082b93c565da593cf6ff476287a9cbd9bf939b2`, 1,756,384 bytes; staged only in isolated target directory. Android tests are compiled, not executed on a phone.

Reproduction helpers: `work/run_scheduler.py`, `work/verify_scheduler.py` (run with the reference `.venv/Scripts/python.exe -I` for pandas/Plotly), `work/scheduler_fixture.py`, `work/test_scheduler_checkpoint.py`.

## Still required

1. Physical scheduler acquisition/configuration acceptance: the last ADB check had no connected device. Availability of `CONFIG_SCHEDSTATS`, runtime scheduler-stat accounting and generic trace support must be measured. Zero captured events are not evidence of zero wait.
2. Native/root eBPF scheduler delay emission is not implemented yet; this slice provides the Perfetto request/decoder/projection path and common protocol/UI. Investigate dynamic tracepoint layout and support before marking the acquisition item complete. Do not substitute scheduler blocked-reason booleans or device Idle.
3. Broader scheduler interaction checks (applied-cohort restore across live updates, original-time window UI on scheduler-only captures) and real-device source evidence remain in the final matrix.
4. Continue hardware queue identity acquisition audit, remaining composite/custom/category/raw-log features, full 43-feature matrix, startup/steady-state/filter/load/memory measurements, then compatible Release backup/install and actual installed launch. Installation remains unchanged in this checkpoint.
