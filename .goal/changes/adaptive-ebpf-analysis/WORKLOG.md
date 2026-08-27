# Worklog — Adaptive eBPF Analysis

## 0001 — 2026-08-27 plan checkpoint

- Classified as `L3 / DESIGN_FIRST / DURABLE`.
- Inspected v0.5 protocol, collector, agent, session loader and egui analysis paths.
- Confirmed that v0.5 already has graph/file Group By foundations while summary, transaction and Explorer paths still contain repeated raw traversal/sorting.
- Planned REQ-201~208 as three release waves with performance foundation before adaptive/deep analysis.
- No production source, test, workflow, existing v0.5 artifact or release state was modified by this planning checkpoint.
- Resume at TSK-201 only after preserving/reconciling the existing dirty working tree.

## 0002 — 2026-08-27 implementation resume

- Reconciled spec SHA-256 and confirmed HEAD `50c22c2bd3b991d8bb1158e809e43fea874942e4`.
- Preserved all pre-existing v0.5 source and release changes in place; no reset or checkout was used.
- Added the deterministic 1M-request `analysis_benchmark` harness for v0.5/v0.6 comparison.
- Local execution is blocked as `ENV`: `cargo` and `rustc` are absent. The harness remains unverified until GitHub CI or a Rust-equipped host executes it.
- Advanced to Protocol v5 implementation without marking TSK-201 performance acceptance complete; TSK-201 remains partial until benchmark evidence exists.

## 0003 — 2026-08-27 v0.8 implementation and CI

- Rebased the adaptive implementation onto released v0.6.0 so the four-workspace ERRC UI and bounded rendering remain intact.
- Implemented Protocol v5 control/aggregate/heavy-hitter/trigger/segment/stack records, kernel filtering and aggregation, adaptive capture, flight-recorder evidence, stack cohorts, background session I/O and live UI controls.
- GitHub Actions run `33051988092` passed format, Clippy with warnings denied, workspace tests, Windows GUI check, Android arm64 agent and eBPF object build.
- The permanent 1M-request analysis benchmark retained 100,000 detailed requests and reported ingest 450 ms, summary 60 ms and graph query 102 ms on the hosted Linux runner.
- NFR-204 Windows p95 frame/selector evidence and NFR-206 physical-device overhead remain manual residual gates; they are not claimed satisfied by CI.
