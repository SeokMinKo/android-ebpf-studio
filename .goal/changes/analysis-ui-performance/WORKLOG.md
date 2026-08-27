# Worklog

## 2026-08-27

- Confirmed per-frame reconstruction in Summary, Pipeline, Explorer, and Events.
- Confirmed Explorer can trigger multiple full transaction scans per request.
- Started a bounded, cached analysis-view refactor from `c499fa7`.
- Added time-bucketed PID/TID/request/sector/transaction indexes and bounded derived caches.
- Added deterministic Explorer sampling (12,000 base / 2,000 graph-backed points), 32-group cap, and explicit File grouping.
- Added 250 ms live analysis refresh, 8 ms message drain budget, bounded RCA cohort, and File table virtualization.
- GitHub Actions run `33035132553` passed format, Clippy, workspace tests, Windows GUI, Android agent, and eBPF jobs at `33f73b05`.
