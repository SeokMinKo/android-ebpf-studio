# Automatic capture and graph selection — local build, 2026-09-06

This extends the existing v0.8.1 attribution implementation. It is not an upstream release. The working checkout is `main` at `bb1bb66`, with previously uncommitted attribution changes preserved. Historical branch names in earlier handoff documents are not the current branch.

## User flow

Connect a rooted Android phone and approve USB debugging. With one authorized device the target is selected automatically; with multiple devices choose one. Start analysis performs root/capability discovery, prepares the collector and starts logging. Stop & analyze drains output, flushes the session and opens Overview. No file picker or mapping configuration is part of capture. Open session and Export CSV are secondary operations.

Preparing, Recording, Stopping, Analyzing, Complete and Error are distinct. A recording cannot restart until the writer finishes. Closing the window during capture asks the collector to stop and waits for finalization. ADB operations have timeouts; a silent collector is terminated after a readiness deadline. Disk write/backlog failures stop capture with partial-data diagnostics. Real device disconnect, disk-full and shutdown recovery still require target acceptance.

Device profiles contain serial, boot ID, build, root method, ABI, tracefs, filesystems, mountinfo and block-device observations. Every Start probes afresh. No model table, user-provided offset or stale phone mapping is reused. Each agent process/session constructs new attribution state. Full eBPF requires supported ABI and successful tracing setup, not just UID 0. Existing dynamic BTF/trace-format adapters and F2FS extent/remap logic remain in use. Failed eBPF startup or unsupported ABI can record per-device `/proc/diskstats`; that fallback has no individual I/O, FilePath, PID/TID, LBA or latency percentile evidence.

## Selection and drilldown

### Scatter appearance

Color Category is visible above Explore's graph (previously Group by inside Advanced). It supports None, Read/Write, Sequential/Random, Small/Large, Process, File, Origin and attribution confidence. Point size controls diameter from 2 to 20 logical pixels. Colors expands a per-group RGB picker, with individual Auto and Reset category colors. Defaults follow the theme; overrides are keyed by category and group identity and stay fixed across theme/filter changes. Legend and point colors match, and selection outlines grow with point size. Appearance changes do not invalidate analysis caches. Preferences are persisted on normal exit. File/process colors are display preferences and do not participate in FilePath attribution.

Explore → Select: click one point or drag a rectangle. The right panel shows Data Count, earliest insert/issue, latest completion, End − Start, Read/Write bytes and MiB/s, chunk-size pies, P50/P90/P95/P99/Max, and Random/Sequential/Unknown pie. Area selection scans all retained plottable requests in the common filters, including points omitted from display sampling. Zoom selection fits those coordinates; Back restores previous plot bounds. Zoom history is bounded to 32 entries.

The panel also lists file candidates and block-issuer processes/threads with count, R/W bytes and maximum total latency. PID, TID and process name remain explicit. File entries carry filesystem device/inode, path and confidence; missing evidence is an Unresolved row, never a guessed path. Multiple file candidates retain their relationships, and their bytes are explicitly non-additive. A block issuer, particularly a writeback worker, is not necessarily the application that originally dirtied the data. File/issuer drilldown uses exact selected request identities, not a broad substring or PID-only search.

Request identity in UI selection/detail is `(opaque request ID, issue timestamp, device major, device minor)`. Selection is a frozen snapshot of the current filtered cohort. Background requests are coalesced; a later selection supersedes earlier pending work. Summary rendering uses bounded list pages. Data rows and numeric legends supplement pie colors. Selection is cleared when a session or axis/query changes. Clear suppresses an in-flight result.

## Definitions and performance boundaries

- Common filters apply to request-oriented Overview, Explore and Investigate: completion time, PID/TID, process name, file/inode, device, R/W and FilePath confidence. Compare and capture diagnostics remain session-wide. Legacy file/syscall evidence tables retain session context; they are not a per-block attributed-byte ledger.
- FilePath coverage is by retained **completed block-request count**, not bytes, syscall count or all physical I/O. Exact requires direct association plus a path; Probable preserves uncertainty; missing paths remain Unresolved even if inode identity is exact.
- Total latency is completion minus insert, or issue when insert is absent. Queue latency requires an insert observation; device latency is issue to completion. Missing components remain unavailable.
- Throughput in the selection panel is selected directional bytes divided by the same earliest-start/latest-completion interval, in MiB/s. Zero duration is unavailable. Percentiles use nearest rank over selected request latencies.
- Random/sequential classification uses the original block issue stream, separately per device and operation. A next sector equal to the previous request's end sector is sequential; first observations are Unknown. Filtering does not reclassify neighbors.
- Overview trend bins are fixed one-second completion-time bins; partial terminal bins are not extrapolated. The log2 latency distribution and its units are shown. No aggregation across stacked diskstats devices is performed.
- The existing engine retains at most 100,000 completed detail records, evicting the oldest 10% at a time. Raw NDJSON remains on disk. This is not arbitrary-size full-session interactive analysis. Loading a large session also materializes raw events before analysis. Time-range replay/paging for earlier evicted requests remains future work.
- Explorer samples at most 12,000 ordinary points or 2,000 graph-dependent points and labels the displayed/retained count. File/graph correlation costs depend on actual evidence density. A 5-second target was measured for the documented fixtures, not guaranteed for every session, machine or kernel.

## Verification boundaries

Host tests, fake-ADB transport tests, native-rendered screenshots and archival physical-session replay are separate evidence classes. No physical phone was available for this build. Fresh Start/Stop capture, two-device adaptation, reboot/reconnect, verifier attach and known read/write workload correctness are unverified. The old physical session demonstrates replay/attribution compatibility, not new collector correctness. Renderer-injected pointer input is not Windows accessibility or human keyboard acceptance. System-theme persistence and all tooltip/axis/filter combinations still need broader interactive acceptance.

## Manual Explorer axis ranges

The Axis ranges editor uses the current AxisMetric units and supports per-axis or combined application. Parsing accepts finite f64 values with finite positive spans. Invalid input does not alter view bounds/history. A single-axis apply preserves the other axis. Manual/Auto/selection Zoom share a 32-entry Back history; bounds changes do not change the selected cohort or analysis filters. Session, metric, and query resets clear stale drafts and restore automatic bounds. Auto refreshes drafts using the final rendered PlotResponse transform, not the previous-frame PlotUi bounds. Style preferences persist; numerical view ranges intentionally do not.

Regression coverage: invalid/inverted/non-finite/overflow spans, partial axis application, bounded history and selection preservation. Native QA verifies Apply, Auto, Back and invalid-input behavior against actual rendered plot bounds; narrow-window QA scrolls using egui mouse-wheel input before activating the control. Archived phone fixtures and synthetic stress data remain distinct from physical-device acceptance.


## Session range replay and exported views (2026-09-06)

Reanalyze time range uses an inclusive completion-time interval with the original session time origin. It streams all block events to preserve original spatial classification and queue metrics, then reloads the selected evidence. Windows above 100,000 completed I/O or bounded evidence capacity fail explicitly and preserve the old view. Cancellation is checked per record. Full-session restore returns the default retained-detail window; the raw source remains authoritative. Source size/mtime are checked around the replay.

File evidence tables use the filtered request cohort's graph nodes and compatible identity/time candidates; they do not create extra exact edges. Export view streams a separate analysis-view NDJSON with filter/window/source metadata, selected summary, completed I/O, all file candidates and transaction graphs. Raw CSV exports stream source records. Export targets cannot overwrite the source session path.

The detail table virtualizes all retained rows and provides Open I/O buttons with stable request identities and keyboard activation. Plot height is independent of outer scroll position. Sampling is stratified by operation so a periodic Read/Write workload cannot disappear through stride aliasing. Missing pipeline endpoints remain unmeasured rather than zero. Raw request-origin nodes and exact pipeline references are bounded by the previous observed completion and the current completion, preserving that lifetime scope through projections and range replay. A conservative 30-second pre-request evidence horizon is applied. Missing/lost boundaries still require physical-device acceptance.

Regression evidence: desktop/tests/reanalysis.rs, protocol/tests/stream_reader.rs, app sampling and file-scope tests; host render harnesses in the delivered source validation-host directory. Physical-device acceptance remains separate.
