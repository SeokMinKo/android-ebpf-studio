# Native scheduler I/O wait checkpoint — Goal remains active

2026-09-07. Extends the schema8 Perfetto/analysis/linked Summary work in
[UPAS_SCHEDULER_CHECKPOINT.md](UPAS_SCHEDULER_CHECKPOINT.md) to the root eBPF collector.

## Implemented

- Optional `sched/sched_stat_iowait` probe reads the target tracepoint format, validating fixed comm16, task pid4 and delay8 fields and offset bounds. Missing/unsupported format or attachment failure leaves other probes available.
- Kernel event kind9 carries delay in the tagged `requested_bytes` slot without changing KernelEvent ABI size. The converter uses waiting-task TID/comm, actual observer CPU (including CPU0), and leaves unknown TGID absent. Request IDs, block device and bytes never become scheduler identities or payload.
- Balanced/Deep/Raw emit all matching scheduler events independently of block-detail sampling. TID capture filters apply to the waiting task. Basic mode and PID/UID/device/operation/size capture filters suppress this population because its missing identities cannot satisfy those filters. Shared ring-reserve loss remains reported; absence of events is never reported as measured zero.
- When the optional probe attaches, a capture-scoped guard verifies `/proc/sys/kernel/sched_schedstats`. An owned 0→1 change is restored on normal stop/error/unwind; an initially enabled setting remains enabled. Restore failures are persisted and shown in Summary. This is not crash-proof: SIGKILL/abort cannot run Drop, and concurrent external profilers do not share a reference-counted ownership protocol.
- Recording/final acquisition metadata is saved as SourceInfo and displayed in the existing scheduler Summary. A new red-then-green regression fixes this auxiliary metadata overwriting the session's loss status, both live and after reload. Actual producer detachment precedes ring draining on stop in the existing collector loop.

Kernel semantics were checked against upstream [scheduler accounting](https://raw.githubusercontent.com/torvalds/linux/master/kernel/sched/stats.c), [tracepoint fields](https://raw.githubusercontent.com/torvalds/linux/master/include/trace/events/sched.h), and [runtime schedstats switch](https://raw.githubusercontent.com/torvalds/linux/master/kernel/sched/core.c). Physical target support still requires actual kernel validation.

## Verification

- Windows-compatible desktop/protocol/types all-target tests: **191 passed, 0 failed, 7 environment-dependent ignored, 32 suites**. Includes host execution of exact agent parser/converter/guard modules: validated layout rejection, zero delay/CPU0, unknown TGID, capture-filter scope, normal restore, panic unwind, external-change preservation and idempotency.
- Android agent check/clippy and Release build passed; Android all-target test binaries cross-built with `--no-run`. They were not executed on a phone.
- BPF Release build passed: **5165 instructions using only R0–R10**. ELF symbol inspection confirms `sched_stat_iowait` and `SCHED_IOWAIT_LAYOUT`. This is not a target verifier or attachment test.
- Compatible desktop clippy `-D warnings`, Cargo fmt and git diff checks passed.
- Actual native GUI, scheduler-only fixture plus acquisition metadata: 200 wait events, 0 block requests, histogram sum200, P50=9us, P95=18us. Trend, same-cohort table and existing right Summary render without clipping in the inspected1600×1200 screenshot. Synthetic source is explicitly labelled. No physical-capture claim.
- Current `adb devices -l` is empty. Prior physical Perfetto capture/save/reload evidence remains valid for that earlier build; the new root probe has no physical acceptance evidence yet.

Evidence under task `outputs/graph-summary-validation/`: `native-scheduler-tests.log`, `native-scheduler-build.json`, `native-scheduler-bpf-symbols.txt`, `native-scheduler-summary.{json,png,summary.csv}`. Reusable helpers: `work/build_bpf.py`, `work/verify_native_scheduler.py`.

Artifacts:

| Artifact | Bytes | SHA256 |
| --- | ---: | --- |
| Android agent Release | 1779456 | fd7e349ac68ce071aee503c1390deb8b708e1b738a550629de881e9ea430be30 |
| eBPF object Release | 53560 | 35e7e48c79de5a87d0edb60b5af6a497ddb3ed4a888bdfe8869191f4bd024392 |

These artifacts are in isolated work targets. Final compatible desktop Release installation remains pending.

## Next work

Hardware queue acquisition/UI, remaining full43 feature reconciliation/implementation, exhaustive matrix/performance and final backup/install/installed launch. Do not mark the full Goal complete at this checkpoint.
