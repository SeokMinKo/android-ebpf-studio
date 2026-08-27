# Design — revision 1

Derived from `spec.md@1`.

## Decision narrative

The product workflow becomes `Overview -> Investigate -> Explore -> Compare`. Operational Diagnostics remains separate. `Investigate` owns request selection and reuses the existing `PipelineView` cache as the single computed detail model. Block and file records are evidence panels in that view, not independent destinations.

`Explore` adds `ExplorerPreset`, a pure mapping to the existing X/Y/Group query tuple. Advanced controls remain available so presets do not reduce capability. `Compare` owns a second `AnalysisEngine` loaded from disk and a cached `AnalysisSummary`; it never mutates the active analyzer.

## Boundaries and invariants

- `StudioApp`: navigation state, comparison baseline, selection and cached view lifetimes.
- `AnalysisEngine`: unchanged event ingestion and analysis truth.
- `SessionReader`: unchanged parsing/integrity behavior for current and baseline sessions.
- Every request-dependent panel consumes one cloned cached `PipelineView`.
- All visible lists have explicit caps; row-heavy detail uses `show_rows`.
- Delta is `current - baseline`; percentage is absent when the baseline is zero.

## Alternatives rejected

- Keep five pages: preserves duplication and weakens the user workflow.
- Recompute each detail panel independently: reintroduces the responsiveness regression.
- Implement cross-session comparison in the protocol crate: no protocol/domain rule changes, so this would add unnecessary coupling.
- Claim automatic root cause from overlap alone: violates the measurement confidence invariant.

## Rollout

Ship as v0.6.0 because navigation and analysis workflow materially change. Existing sessions remain readable. Rollback requires only restoring v0.5.1 binaries.

