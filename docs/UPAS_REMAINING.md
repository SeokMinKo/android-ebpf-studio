# Remaining work and worktree cleanup

User requested the remaining-work report and worktree cleanup on2026-09-07. Feature implementation stopped at that request. The full Goal is **not complete**. This document records the current state; it does not authorize automatic restoration of unfinished changes.

## Preserved state

- Completed feature implementation through `259e46e4aef6df55cc44e60e1ea2b79bdf1c6e03` on `feat/upas-io-analysis`.
- Independent backup branch: `backup/upas-before-cleanup-20260907`, pointing to that same completed implementation.
- Unfinished hardware queue changes: stash `beafa50e0ac2b99362f9ebed7e7936e6c532e02c` and task `outputs/worktree-cleanup/hardware-queue-in-progress.patch`.
- Patch SHA256: `91aad08ff45e7cc9595304bb5ae3c228597fb68a744b68bf3c544c5bece92163`. Stash diff was compared byte-for-byte with the independent patch before confirming cleanup.
-29 modified tracked files were preserved. Working tree/index were clean after stash. This documentation is committed separately so the final working tree remains clean.
- Worktree directory, completed branch, saved traces, QA evidence, build artifacts and installed application are retained. No merge into main or deployment was performed for cleanup.

The stashed HW Queue experiment is **not build-verified**. It adds optional issue/completion queue fields, proposes schema9, and starts a native tracepoint layout path. Last check failed because the offset-field rename landed in SchedulerWaitLayout while TraceLayout still had `reserved`; no UI or end-to-end queue acquisition acceptance exists. Review before any future `git stash apply beafa50e0ac2b99362f9ebed7e7936e6c532e02c`; do not treat this stash as completed functionality. The retained clean implementation remains schema8.

## Remaining implementation

1. **Hardware queue**: finish validated queue ID acquisition, protocol/storage/reload, independent issue/completion phase identity, device scope, Trend and linked Summary. CPU/tag/doorbell/software QD must not substitute for a queue index. Investigate target-validated BTF request/hctx support where formatted tracepoints omit the queue; source limitations must have evidence.
2. **Overall/custom surfaces**: composite Footprint/QD/Chunk view; remaining custom categorical axes and paired Chunk/QD/custom histogram controls; check all selectable uPAS semantics against current implementations.
3. **Raw log/detail navigation**: finish source-backed Raw Log and data-table navigation audit, preserving actual selected request/source correspondence.
4. **Feature matrix reconciliation**: Footprint/Overwrite/Chunk/Latency distributions already have implemented and individually tested slices, but some rows retain partial status. Complete missing per-feature correspondence/verification instead of counting all partial rows as absent implementations or complete parity.

## Integration and final validation

- Current original checkout is clean on main `dbb002fcf68999305482a057b9ed867136a1848e`. `git rev-list --left-right --count main...HEAD` at cleanup was20/14. main has20 commits absent from this feature branch, including PR12–19 changes for post-Stop ingestion, Perfetto startup/fallback recovery, unsupported clocks, latency drilldown, whole-session FilePath coverage, activity caching and observed QD. Integrate and verify these changes before final deployment to avoid regressing the newer installed behavior.
- Run one complete43-feature matrix using real, deterministic, empty, single-event, Read/Write-only, missing-field, selected-range/filter and large-data inputs. Existing slice evidence does not establish that final whole-matrix gate.
- Measure baseline/current loading, filter application, rendering and memory on identical large traces. Distinguish startup from steady-state performance; resolve material regressions.
- Validate new root scheduler/queue probe verifier, attachment and recording when suitable hardware is available. Latest ADB list was empty. Earlier physical Perfetto capture→Stop→save→reload passed, but does not validate newly added root probes. If hardware remains unavailable, explicitly retain that physical-validation limit while completing simulator/offline work.
- Build compatible desktop/agent/eBPF Release, back up installed files, preserve sessions/settings/logs, install to the requested AppData path and verify actual installed launch. The feature branch has not been installed.

Current installed manifest was reread during cleanup: build `observed-queue-depth`, source commit `f13ff0be4b201c4e22ed7401b6398820989b5d3b`, desktop SHA256 `f5fee61ec7b49f153e563af296c57a3bc6fdecd236b0e1117287229abe296425`. These are manifest contents, not a fresh hash verification of every installed file.

## Current completed evidence

- Main-Trend-linked Summary distributions, LBA address overlap counts, grouped footprints and Host BW implementations are described in the linked checkpoints in UPAS_PROGRESS.md.
- Latest collector checkpoint:191 host tests passed/7ignored; Android Release and test-binary cross-build; BPF register/symbol checks; physical acceptance separate.
- Latest Summary checkpoint: desktop library92passed/2ignored, compatible lint; native8247-I/O exact Chunk categories, Read7415/Write648/point1/empty0/scroll; raw-record/CSV and actual four-function uPAS plotting-code comparisons passed.
- See `UPAS_NATIVE_SCHEDULER_CHECKPOINT.md`, `UPAS_CATEGORY_CHECKPOINT.md`, `UPAS_FEATURE_MATRIX.json`, and task `outputs/worktree-cleanup/cleanup.json` for detailed evidence.
