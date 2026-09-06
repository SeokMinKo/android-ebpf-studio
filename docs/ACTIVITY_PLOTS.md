# Activity plot rendering and drilldown

Overview uses fixed one-second bins by completion time. The IOPS and throughput
plots, rankings, request KPIs and filters describe the same retained completed
requests. Whole-session FilePath coverage has its separately labeled denominator.

The activity cache now holds immutable shared trend data and precomputed plot
coordinates. Ordinary frames borrow that cache instead of cloning every time bin,
process row and coordinate. A filter change, analysis generation change or session
reset invalidates it. The busiest interval is computed with the cache.

Dense displays choose a resolution according to the visible time range and pixel
width. Each successive level keeps the first, minimum, maximum and last original
sample from groups of 16, ordered by time. No averages, synthetic zeroes or new
timestamps are introduced. Full bounds come from the original series. Zooming
reveals finer levels; all original bins remain available to analysis and filters.
The caption reports displayed versus full time-bin point counts. Sparse or missing
time ranges are not joined by lines.

Clicking either activity plot opens the corresponding half-open one-second
interval in Explore, preserves other filters, and automatically fills Selection
Summary with those requests. The native regression exposed that the previous
click path applied the filter but left Summary empty; both plots now select the
filtered population. Compare continues to own independent baseline/current
selections, files, processes and Zoom/Back histories.

## Repeatable checks

```text
cargo test -p android-ebpf-studio --features gui --lib activity
node scripts/check-activity-plots.mjs <release-exe> <saved-root-session> <new-output-dir> activity-view light
node scripts/check-activity-plots.mjs <release-exe> <saved-root-session> <new-output-dir> activity-iops light
node scripts/check-activity-plots.mjs <release-exe> <saved-root-session> <new-output-dir> activity-throughput dark
node scripts/check-activity-plots.mjs <release-exe> <dense-root-session> <new-output-dir> activity-zoom contrast
```

The Node.js 24+ script launches the actual native renderer, injects pointer or
zoom input, and checks the resulting page, time filter, exact selected request
keys, preserved source hash and screenshot. For a dense fixture, zoom must narrow
the range and reveal finer samples. The static-view check applies an opt-in
16.7 ms p95 **UI update** budget with at least 20 samples. This is a component
budget on the test host, not measured GPU/vsync latency or a portable CI promise.
Click/zoom action completion uses the user's five-second budget.

The diagnosis used a labeled synthetic source with 100,001 block completions and
90,001 retained bins. Native UI update p95 was 29.296 ms before changes. Removing
all file attribution evidence still reproduced 34.718 ms; shared data alone
reached 25.847 ms and cached coordinates 20.518 ms. Adaptive display reduced the
full-source run to 1.246 ms p95 (41 samples), with a 508.573 ms maximum including
initial work and 949.854 ms source loading plus coverage. The original source and
whole-session coverage oracle were unchanged. These sequential local probes are
diagnostic observations, not controlled cross-machine benchmark guarantees.

Host regressions cover extrema/endpoints, sparse gaps, zoom resolution, immutable
source samples, reuse across frames, invalidation after filtering/session reset,
and activity-click Summary membership. Release evidence records native theme,
click/zoom, Compare and latency regression results separately. Long physical Stop
timing, root memory scaling, second-phone acceptance and the full UI/accessibility
matrix remain open in [the acceptance ledger](ACCEPTANCE_STATUS.md).
