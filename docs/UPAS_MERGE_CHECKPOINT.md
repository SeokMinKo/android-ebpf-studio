# Selected uPAS scope and main integration — 2026-09-07

The user's selected items2/3/4 are implemented and verified for this merge. The original full Goal remains incomplete: HW Queue, native scheduler support for the available Vivo kernel's dynamic `comm` layout, and final installation remain in [UPAS_REMAINING.md](UPAS_REMAINING.md).

## Resulting behavior

- **Overall** adds linked LBA, observed device QD at issue and Chunk graphs. Main LBA selection supplies one request cohort to the existing right-hand Summary. Companion point selection and shared filters work. uPAS `draw_overall_graph` actually delegates to whole-session `draw_overall_footprint`; this composite is an intentional Studio extension and follows current filters.
- **Custom** supports numeric and seven categorical axes, Scatter/Line/Bar, full category labels, and two independent companion distribution panels. Domains are established from the full filtered cohort before display sampling/selection; PID/device and file candidate-set identity remain explicit. Category positions have count/payload summaries, never numeric percentiles. Individual bars at equal X overlap; they are not grouped sums.
- **Raw Log** opens exact saved request records from Investigate. NDJSON matching includes request ID, device and phase timestamps; reused IDs cannot join a different lifetime. Original Perfetto completion and candidate issue records are distinguished from the derived projection. Reading occurs in the background; Copy/text export preserve the displayed source text.
- **Trend-linked Summary** retains graph-specific histogram/percentile/CDF, LBA violin and Read/Write overlapping address counts, categories, Files/Processes and Host BW. No separate aggregate-graph catalogue was introduced.

## Integration and regressions

Main `dbb002f` (20 intervening commits) was integrated in `efad262`. This preserves bounded post-Stop ingestion, Perfetto ownership/fallback/recovery, unsupported-clock semantics, latency drilldown, whole-session FilePath coverage, activity caching and Compare. Existing axis indices0–18 remain stable; main's all-device issue QD is index19; categorical axes append at20–26. All-device QD and device-local issue depth have distinct labels. Schema8 remains compatible; the HW Queue schema9 experiment is not applied.

Unsupported-clock rows were found in added Footprint/Timeline/window paths and excluded from time graphs and completion-time CSV cells. Non-time count/byte information remains available; missing measurements are not zero. Independent clock regressions cover28 presets.

Physical capture exposed expensive Overview transaction attribution on the UI thread. A saved dense root trace reproduced4,505ms synchronous computation in GNU debug. Overview and its retained KPIs now compute on a background snapshot, with filter/session invalidation and bounded refresh. The same trace's UI enqueue took62ms and its613-request background result was verified. Capture automation also used press/release four slow frames apart, producing a long press; a600ms-frame regression now verifies a real egui button click. Table keyboard automation waits for scroll/focus stabilization and always releases Enter.

Obsolete full-graph Summary jobs were also retained after a filter/axis change. The receiver now owns a cancellation flag, invalidation signals it, and request aggregation exits without publishing partial/empty results. Numeric, window and Timeline Summary paths share this cancellation. Two regressions failed before the fix and passed afterward; seven representative native feature routes were rerun. Source implementation commit: `777c78d`.

## Verification

- Host all-target tests: **227 passed, 0 failed, 11 intentionally ignored**; desktop library110 passed. A separate ignored real-trace performance probe was explicitly run and passed. Clippy with warnings denied, fmt and whitespace checks passed. Compatible desktop Release, Android arm64 agent Release and BPF object built successfully; BPF register validation passed.
-43-feature correspondence reconciled: **42 non-HW routes rendered**; HW Queue is explicitly deferred. The99-case native matrix includes46 Read/Write preset cases, seven categorical axes and two geometries. Separate scheduler fixtures verify200 and90,005 delay samples; raw-reanalyzed real rolling distributions verify8,183 samples and independent P95 values. Native point/empty/process/PID/paired-histogram/Raw Log checks supplement the matrix. The two original scheduler render cases had an inapplicable device filter and zero population; they are not acquisition evidence and are superseded by these nonempty fixtures.
- Engine matrix:336 preset/cohort combinations (empty, single, mixed and10,005 rows; All/Read/Write), plus28 unsupported-clock preset checks. Histogram totals, exact expected values, categories, request counts, Busy/Idle and CSV population checks are independent of display downsampling. Prior per-feature uPAS AST/oracle checkpoints remain linked from the feature matrix.
- Existing main: QD Explore and Compare, activity IOPS/throughput drilldown, whole-session coverage, three latency interactions and eight Compare interactions passed. An initial coverage process timed out; identical source reruns in dark and light passed with preserved hashes. Initial Raw Log keyboard harness failures were corrected and the actual Open I/O → Investigate → loaded-source transition passed.
- New root capture on Vivo V2606A / Android17: Start →12s recording → Stop → saved → reopen completed. Final run had544,972 event records,64 completion records,63 paired requests, one unmatched completion, **0 stored dropped/rejected records**, graceful footer. Stop to Complete was1,743ms. Completion CPU2 was present in all64 raw completions and all63 reloaded request summaries. This is observed detail, not proof that every kernel I/O was emitted.
- Final capture UI P50/P95:1.49/2.51ms; maximum403ms including transient work. It is not a claim of a hard frame deadline. Saved `sched_stat_iowait` metadata reports unavailable attachment: `__data_loc char[] comm` is4 bytes whereas the current probe requires a fixed16-byte array. No scheduler samples were fabricated. `sched_schedstats` remained1 before/after, and no agent process remained.

## Same-input performance comparison

GNU Rust1.98 **debug** binaries, main `dbb002f` versus integrated feature, three alternating repetitions per case,48 native runs total. Real input has8,294 requests. Large input repeats and retimestamps actual observed requests to150,000 records (164.5MiB); detail retention leaves100,000 (Read filter89,718). It is a repeatable stress fixture, not a fresh hardware workload. Both builds have identical filter timing instrumentation. Build/test/capture processes were idle during this comparison.

| Input / view | Load ms main → feature | Filter ms | Plot rebuild ms | Peak RSS MiB | UI median ms |
|---|---:|---:|---:|---:|---:|
| real / Latency / All | 257.4 → 303.4 | not applied | 10.0 → 11.4 | 226.0 → 242.7 | 6.5 → 8.1 |
| real / Latency / Read | 258.4 → 287.2 | 11.3 → 11.4 | 9.5 → 11.1 | 231.0 → 247.5 | 6.7 → 7.8 |
| real / LBA / All | 263.1 → 295.1 | not applied | 9.1 → 9.8 | 223.4 → 244.7 | 4.8 → 7.6 |
| real / LBA / Read | 256.5 → 297.2 | 11.9 → 13.1 | 8.9 → 11.4 | 229.4 → 251.4 | 4.2 → 7.2 |
| large / Latency / All | 4446.4 → 5133.3 | not applied | 15.0 → 18.1 | 297.9 → 423.4 | 7.4 → 8.5 |
| large / Latency / Read | 4289.2 → 5012.2 | 144.3 → 143.7 | 13.8 → 14.0 | 363.5 → 488.4 | 7.5 → 7.8 |
| large / LBA / All | 4372.2 → 4986.4 | not applied | 13.9 → 14.8 | 290.6 → 426.2 | 4.0 → 4.3 |
| large / LBA / Read | 4329.7 → 4907.0 | 140.9 → 141.5 | 14.0 → 14.6 | 357.8 → 494.4 | 3.8 → 4.0 |

Cancellation reduced the large Read-filter peak RSS from567.2 to488.4MiB and LBA Read from581.6 to494.4MiB in repeated same-machine runs. Filter application is now143.7ms versus main144.3ms (Latency Read), and141.5ms versus140.9ms (LBA Read). The fix eliminates obsolete request aggregation; it does not remove the cost of the new full-cohort result itself.

Large-input loading remains roughly14–17% slower (4.9–5.1s versus4.3–4.4s in debug); peak RSS remains about125–137MiB above main. These are explicit costs, not a zero-regression claim. Median plot rebuild is14–18ms, and large-input median UI work4–9ms. Full native process time including Summary readiness and export is about16s versus9s in debug. The main baseline does not automatically construct these new summaries. Both the initial48-run comparison and final48 completed cases are retained; one baseline process exited without a report and its identical retry passed.

Memory is a25ms sampled **whole-process peak including screenshot, I/O CSV and new distribution CSV export**, not idle working set or isolated cache size. The harness loads an initial view and applies the requested preset/filter after its first frame, so startup includes that change. On short real-input runs an extra Summary initialization frame affects P95; it must not be presented as steady-state latency. The table reports median UI frame work separately. Live blocking was addressed using the dense physical trace. Release capture timings must not be compared numerically with debug load timings.

## Reproduction and evidence

Compact machine-readable results, exact binary hashes and performance tables are in [validation/upas-merge-20260907.json](validation/upas-merge-20260907.json). The task workspace retains original native JSON/PNG/CSV, debug/Release binaries, full48-run results, failed-before/fixed-after logs and saved captures under `outputs/`. Raw traces/screenshots are intentionally not checked into Git.

Reusable tools:

```text
python scripts/check-upas-matrix.py <gui-exe> <observed-session.ndjson> <new-output-dir> --scheduler-small <fixture.ndjson> --scheduler-large <large.ndjson>
python scripts/measure-upas-performance.py <baseline-exe> <feature-exe> <real.ndjson> <large.ndjson> <new-output-dir> --profile <exact-toolchain-profile-and-baseline>
cargo test -p android-ebpf-studio -p android-ebpf-protocol -p android-ebpf-types --features gui --all-targets
cargo clippy -p android-ebpf-studio -p android-ebpf-protocol -p android-ebpf-types --features gui --all-targets -- -D warnings
```

The native matrix expects a bounded Perfetto-projected source with observed completions on device8:0; its source assumptions are explicit. Main's `check-queue-depth.mjs`, `check-activity-plots.mjs`, `check-filepath-coverage.mjs`, `check-latency-drilldown.mjs` and `check-compare-interaction.mjs` retain their CLI usage. See per-feature prior checkpoints for collector/CPU/window/BW definitions and source-specific limits.

The compatible Release bundle was launched and physically exercised from the task's QA bundle. After the final graph-summary cancellation change, desktop Release was rebuilt and the saved63-request root capture was reopened in Overall; final binary hashes are recorded separately from the physical-capture bundle. **The installed application was not replaced.** Hardware-queue WIP remains in the named stash, verified independent patch and backup branch. No full uPAS parity or full original Goal completion is claimed.
