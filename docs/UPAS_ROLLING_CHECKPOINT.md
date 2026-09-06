# Rolling trend continuation — Goal still active

2026-09-07. Existing Explore Summary follows its current main Trend. No separate aggregate catalogue was added. Installed executable has not been replaced.

## Implemented

- Rolling C2C and D2D bandwidth presets18/19 and request axes17/18. One rate per endpoint request,64 same-device observed gaps and aligned R/W bytes. O(1) bounded accumulator; no partial warmup, fabricated missing values, or cross-device windows.
- Raw protocol correlation and Perfetto projection populate optional backward-compatible DetailTiming rate fields before analysis filters/retention. Unknown correlation payload invalidates its window. Older saved observed sessions remain unavailable until original raw data is reanalyzed.
- Linked histogram, exact percentiles, CDF, sorted ranks and graph I/O CSV. Export includes exact C2C/D2D payload, duration and MiB/s. Read/Write tabs classify endpoint operations; rates still contain the original device-wide R/W payload.
- Fixed a newly discovered missing-metric state: no plottable I/O formerly displayed zero graph BW. It now displays unavailable graph payload/rates while retaining independently known source activity. An actually empty filter is distinct. Added a regression test.

## Evidence

- Native existing raw-reanalysis UI recovered8294 requests from the real Samsung trace. For device8:0, each clock has8183 valid samples; the Read endpoint filter has7383. Original-event Python oracle matched every rate payload/duration, histogram bin, percentile, sorted-rank CSV and detailed export.
- C2C P50=222.47157034625448 and P95=745.6963350442666MiB/s. D2D P50=224.92176667671492 and P95=746.0936220737058MiB/s. These describe this trace, not general device performance.
- Native screenshots reviewed for rolling C2C and an older observed session without rate fields. Older session:8247 source I/O,0 metric samples, null percentiles/BW and unavailable CSV payload. Legacy184-request raw eBPF session recomputes120 valid rates on reload.
- Executed actual uPAS assignment AST on equal deterministic130-event input. Its ws=64 despite title32 and its denominator adds the first cohort request's service time. It yields64.5ms/0.969MiB/s, versus explicit64-gap duration64ms/0.9765625MiB/s here. See analysis contract; numerical parity is deliberately not claimed for this ambiguous formula.
- Compatible desktop/protocol/types all-target tests passed; desktop lib75 passed/2 environment-dependent ignored. Protocol correlation6 passed, projection7 passed. Compatible Clippy with -D warnings passed. Linux-only agent/eBPF targets were not verified by these Windows checks.
- Task evidence: outputs/graph-summary-validation/rolling-all-tests.log, rolling-clippy.log, rolling-oracle.json, rolling-upas-comparison.json, rolling-reanalysis.json and rolling-*.png/summary.csv/io.csv. Reproduction helpers: work/verify_rolling.py and work/compare_rolling_upas.py (run latter with python -I to avoid the task's inspect.py shadowing Python stdlib).

## Required remaining work

Continuous Busy/Idle interval trends/distributions, idle-separated bursts, connected footprint/Timeline/Gantt; feasible acquisition extensions for missing fields; complete43-feature corresponding-input/real/synthetic/missing/large graph matrix; all filter/selection semantics; before/after performance and memory; compatible Linux/Android artifacts; source/manifest recheck; Release backup/install and actual installed launch. Current phone has no su, so physical eBPF acceptance remains separately unavailable; Perfetto capture/save/reload was verified in the previous checkpoint. Continue useful local work; this is not overall Goal completion.
