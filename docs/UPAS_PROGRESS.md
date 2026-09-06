# Active goal checkpoint — not overall completion

Read the full objective at `C:/Users/AEBIZTRIP5.pub/.codex/attachments/700d9658-a88e-4c81-bb21-c455bd9eb2b2/goal-objective.md`. User subsequently clarified that Summary means the **existing Explore right-hand Summary inspector linked to the main graph**, not Overview or a separate histogram/pie catalogue. This supersedes the initial topology interpretation. Continue all remaining objective work autonomously. Goal remains active.

## Source/workspace

- Worktree `C:/Users/AEBIZTRIP5.pub/Documents/Codex/2026-09-06/new-chat-3/work/android-ebpf-studio`, branch `feat/upas-io-analysis`, base `743a348`.
- Original checkout was clean when branched. Later original checkout gained an unrelated `crates/desktop/src/qa.rs` change from outside this worktree. Do not overwrite/merge it blindly. Recheck source/install manifest before final deployment since another task may still be active.
- Installed manifest initially matched base commit/tree, but current manifest has no source path field. Initial EXE SHA256 `682f3323f8c8727fbe1e972711e3e7ca029efc306434cc6d150b666cb4ddebc5`.
- No applied AGENTS.md found in source/ancestors or repo. uPAS reference remains unmodified.

## Implemented slice

- `graph_summary.rs`: exact nearest-rank percentile distributions, equal-width histogram with explicit last-bin inclusion, no fabricated NaN/zero, device-separated interval-sweep Read/Write address overlap counts (no per-sector expansion).
- `graph_summary_ui.rs` included in app: graph-axis-specific Summary, Total/Read/Write/Other choice, histogram counts table, percentiles, per-device LBA histogram/optional binned-density violin, repeated-address table and optional count graph, CSV same values/definitions. Y metric drives summary, X when Y is time.
- `selection.rs`: compute summary from every full-resolution plottable request, not display downsampling; missing-axis source count; cached background full-filtered graph summary when no explicit selection; selected-region summary and Clear fallback; live snapshot refresh avoids starvation and stale query caches.
- Main graph has added Chunk and QD timeline presets (existing six preset indices preserved). Existing Overview, Pipeline, Compare, source capture untouched.
- QA reports `graph_summary` and accepts `ANDROID_EBPF_QA_Y_AXIS` index. Existing native eframe QA supports rectangle/point gestures and panel scroll; source-backed screenshots are actual renderer output, not mockups.
- `UPAS_FEATURE_MATRIX.json`: all 43 GraphFigure selectable entries, source lines/fields and evolving calculation/target notes. It is explicitly partial/pending, NOT evidence of parity completion.

## Build/tool environment

- PowerShell dies with CET. Use `exec_command` with `shell=cmd.exe, login=false`. Bare `type` requires backslashes; simple unquoted paths avoid cmd quote issues. Python default cp949; scripts use stdout UTF-8.
- No MSVC linker installed. Existing working toolchain: `cargo +1.98.0-x86_64-pc-windows-gnu`, add `C:/Users/AEBIZTRIP5.pub/Documents/Codex/2026-09-03/new-chat-2/work/toolchains/mingw64/bin` to PATH.
- Wrapper `../build.py` run from generated project root as `python work\build.py ...`; sets repo and isolated `work/target` (do not overwrite original checkout's build directory). Release link takes ~1m45s after GUI changes.
- `cargo clippy --workspace` fails because Linux-only aya-obj requires std::os::fd on Windows. Desktop/protocol/ebpf-types lint passes. Agent checks need Linux/Android toolchain, not a fabricated Windows pass.
- NDK r29, mingw64 and bpf-linker exist under original task `work/toolchains`. No new tool installation required so far.

## Evidence so far

- Desktop lib: 54 passed, 1 physical-device test ignored. All desktop/protocol/types all-target tests passed with existing environment-dependent transport/device tests ignored. 100K selection test <5s passes.
- Windows-compatible Clippy with -D warnings, fmt check, diff check pass.
- Release built and actually launched from worktree. **Installed EXE has not been replaced**; backup/install is pending full goal.
- Native real saved trace: `C:/Users/AEBIZTRIP5.pub/Documents/Codex/2026-09-03/new-chat-2/outputs/file-attribution-validation/capture.ndjson`, 184 completed I/O.
- `../summary_matrix.py`: 19 native cases (12 axes; R/W/FilePath filters; area and single point; 800x600; Summary scroll). All passed. `outputs/graph-summary-validation/matrix.json` has results. UFS axis is correctly empty (no measured samples), not a measured zero.
- `../verify_reference.py`: independent Python raw-event pairing oracle verified histogram bins and P50/P95 for 8 axes and all 20 address ranges. Example repeated LBA 994704–994712 = 11 reads + 1 write; cross-operation overlap is included as repeated address access.
- Screenshots reviewed: baseline-lba, axis-01 (LBA), axis-03 (Chunk), chunk-small, lba-counts. New percentile layout compacted; small panel intentionally vertically scrolls. Existing narrow main control row clips Point size text (unfixed baseline issue). LBA default grid showed only tick 0; latest source adds `summary_grid` custom ticks. Final build/rerender of that last fix must be recorded.
- Baseline single-run Release 184-I/O Explore UI p95=1.633ms; linked Release LBA p95=1.409ms in matrix (no generalized performance claim; full memory/large trace performance still pending). Protocol 100K baseline: ingest114ms, summary105ms, graph150ms.
- ADB current device: RFKYB09QXYD / Samsung SM_F966N. Actual capture/root capability is not yet tested this goal. Older saved trace came from a different kernel/device, so keep live device acceptance separate.
- Last source built successfully in Release after `summary_grid` fix. `final-lba.png` and `final-chunk.png` native rerenders preserve 184 samples and correct percentile/bin values. Final LBA UI p95=1.659ms, within single-run noise of baseline 1.633ms. Windows-compatible Clippy/fmt pass on latest source. All test/native-matrix runner sessions have completed; no known build process is pending.

## Required remaining work

1. Finish full uPAS function/filter/formula inventory, correspondence table and per-feature validation. Do not count pending labels as implemented features.
2. FilePath/Process lanes now implemented in `footprint_ui.rs`: linked axes, all-group pagination (4/page), lane filter, point/area selection, device/PID separation, origin-candidate labeling, full-resolution statistics. Native real-trace FilePath/Process renders and point/area gestures passed. Further full matrix/performance and lane pagination GUI checks remain.
3. `host_bw.rs` and `host_bw_ui.rs`: full-source activity union survives display retention/window eviction, computed before Process/File filters; clipped explicit range, Total/R/W, UI and CSV. Overlap/multiple devices/other processes/zero-denominator tests pass. **Acquisition completeness is still not proven in production, so true Idle and w/o Idle remain unavailable with an observed active-time lower bound. This is NOT completion of the Host BW goal. Implement supported capture coverage/extensions and validate before marking parity.**
4. QD semantic difference: existing `queue_depth_after` is after completion; uPAS `send_q` is issue depth. Current QD histogram correctly summarizes existing axis but this is not yet uPAS issue-QD equivalence.
5. Missing analysis trends/paired aggregates: D2D/C2C, normalized latency, fixed-time and rolling BW, busy/idle, cumulative/realtime data, temporal locality, custom category pies, CPU/layer/hardware queue/IOWait as supported by source/capture. Extend collection/protocol/storage if viable. Preserve file-confidence rules.
6. Existing Process comm/PID/TID filter works in basic regression; verify actual GUI input/change/clear, same-name different PID, missing names, empty combination, all new surfaces and CSV. Add size/access/layer/etc filters as required. Capture PID filter separate from analysis comm search.
7. Broader complete graph matrix, equivalent uPAS comparisons, large trace before/after load/filter/render and memory, simulator and current physical capture/save/reload. Current 19 scenarios only cover the linked-summary slice.
8. Final full goal Release build, recoverable backup and install to AppData/Local/Programs/AndroidEbpfStudio; preserve settings/sessions/logs; compatible agent/object; manifest with source path/hashes; actual installed launch; concise Korean final report. Do not mark goal complete until these are handled.

## Latest continuation slice

- Added common size, access-pattern, issue-CPU and observed-layer filters; all five operation categories. Labels clarify issuer comm vs package/original process and acquisition filters.
- Added Apply selection to analysis filters so selected keys/range propagate to the existing common table/export/filter cohort.
- Actual native TextEdit test (`process-input.json` and `filter-*.csv`) entered mixed-case F2FS, changed to an absent process, then clicked Clear. Main filtered engine/lane unique/Summary/CSV populations =17,0,184. Device-wide observed busy=105309209 ns and interval=7484059007 ns remain constant across these filters. `../verify_filters.py` passed.
- Desktop lib 61 passed/1 physical ignored; reanalysis6 passed including100020-I/O activity preservation across retention and partial loading. Compatible Clippy passes. Cargo fmt applied; included UI files keep existing include-file style.
- Native lane rectangle initial QA attempted input on an axis margin and timed out. Harness now targets actual plot transform frame; repeated actual gesture succeeded selecting2 first-lane I/O. File lane point selects1. These are actual eframe gestures, not direct state mutation.
- Current phone RFKYB09QXYD: adb shell uid2000; `su` absent. First actual capture GUI attempt reached Start but could not find agent/object beside worktree binary; no capture started. Copied installed matching artifacts into isolated debug target; second attempt pending. Do not claim first timeout as device capability failure.
- Original source is now8951e4d (PR11), with new commits851df0d andf4f21c0 since base743a348. These fix long-capture responsiveness and retained Overview summary scope. Must integrate them before eventual install; do not regress these installed fixes. Original checkout currently clean.
- No Goal completion, no installation of this feature branch, no full uPAS parity claim yet.
