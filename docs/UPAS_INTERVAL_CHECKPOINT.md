# Continuous activity continuation — Goal still active

2026-09-07. Existing right Explore Summary remains linked to the main Trend. Prior rolling work is committed as92ef1dc. No installation or full uPAS parity completion is claimed.

## Implemented and verified

- Explore presets20/21: Continuous busy / idle intervals. Full-source selected-device activity merges overlap and adjacency; Idle is the complement. One positive interval per histogram/percentile/CDF sample, clipped at analysis bounds. Unknown coverage cannot fabricate Idle. Existing fixed-window activity presets remain distinct.
- Main scatter uses interval centers and durations; point/area selection summarizes whole intervals, with the same interval CSV. Full graph request cohort includes all filtered analysis-range I/O; selected interval request cohort uses completion (start,end]. A Busy closing completion is excluded from the following Idle gap. Multiple selected intervals use the explicitly labelled first-to-last time envelope for Host BW; Y filtering changes payload within that clock.
- Deterministic tests cover overlap, touching endpoints, device union, clipping, full idle, zero range, unknown coverage, independence from another-process filter, one-sample-per-run weighting, Busy point selection and zero-request Idle selection/CSV.
- Real Samsung device8:0 trace:8247 I/O,2758 Busy intervals and2757 Idle intervals. Busy P50=.111511ms/P95=.478906ms; Idle P50=.036511ms/P95=10.182344ms. Raw independent oracle verified every interval boundary, request/payload count, histogram and percentile, CSV and both BW results. Total Busy532653188ns and Idle6880229153ns match previous Host BW verification.
- Native GUI: full Busy/Idle, Read filter (7415 requests, unchanged2758 Busy intervals), Busy point (1 interval/2 I/O), Idle point (1 interval/0 I/O), rectangle (285 intervals/540 I/O) passed. Screenshots of full Idle and final-labelled Idle were inspected. Legacy184-request unproven source renders unavailable interval distribution, retaining known request payload and unavailable w/o Idle.
- Actual uPAS parser and four analyzer assignments executed on equal three-request overlap fixture. Its Busy values depend on complete_q==max_qd_value-2 and inter-completion spacing, with zero-filled request rows; these are not continuous union durations. Formula/population difference is documented in the contract instead of copying it silently.
- Compatible all-target desktop/protocol/types tests passed: desktop lib77 passed/2 environment-dependent ignored; existing transport/device fixture skips remain. Compatible Clippy passed, followed by final formatting/Clippy checks. This is Windows host evidence, not a Linux/eBPF target build claim.

## Evidence and next work

Task-local evidence: outputs/graph-summary-validation/interval-oracle.json, interval-upas-comparison.json, interval-all-tests.log and interval-*.json/png/summary.csv/io.csv. Helpers: work/verify_intervals.py, work/compare_intervals_upas.py (python -I), work/checkpoint_intervals.py. Oracle is independent of the Rust interval implementation and reads original saved observations.

Remaining required scope: idle-separated cumulative bursts; connected footprint/Timeline/Gantt; feasible acquisition extensions for missing hardware queue/IOWait fields; full43-feature real/synthetic/missing/large graph and corresponding-input matrix; Apply/Clear/filter edge semantics across every surface; before/after performance and memory; compatible Linux/Android artifacts; original source/manifest recheck; Release backup/install and actual installed launch. Current phone lacks su; actual eBPF acceptance remains a separate physical-device constraint. Continue local work rather than treating that as a global block.
