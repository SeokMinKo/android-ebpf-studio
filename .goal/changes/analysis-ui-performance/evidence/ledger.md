# Evidence Ledger

| Requirement | Evidence | Status |
|---|---|---|
| No unchanged-frame recomputation | Derived cache implementation + CI | Pass |
| Bounded Explorer rendering | `explorer_sampling_is_bounded_and_spans_the_session` | Pass |
| File grouping preserves ambiguity | `file_group_uses_path_and_preserves_multiple_origins` | Pass |
| Bounded live ingestion | 8 ms / 1,000 message frame budget | Pass |
| Bounded RCA cohort | `slow_reason_bounds_large_cohort_work` | Pass |
| Rust/Windows/Android/eBPF gates | GitHub Actions `33035132553` | Pass |
