---
change_id: analysis-workspace-errc
revision: 1
level: L3
execution_mode: DURABLE
route: DESIGN_FIRST
confirmation: CONFIRMED-AUTO
lifecycle: SATISFIED
confirmed_by: current user implementation request
baseline: v0.5.1 / 172549f0ce8b3ec52244e047f88c3b982fe95d9f
---

# Analysis workspace ERRC specification

## Problem and goal

[User] The five analysis pages are fragmented and the application must remain responsive on large captures. The user wants the previously proposed ERRC information architecture implemented.

[Repo evidence] v0.5.1 already caches Summary, Explorer, and per-request Pipeline data, bounds plot samples, and exposes file attribution. The same evidence is still spread across Summary, Pipeline, Block Events, and File I/O pages.

The goal is a four-workspace analysis flow: understand the session, investigate one request, explore a hypothesis, and compare against a baseline. Technical evidence remains available without dominating the default workflow.

## Scope fence

- Included: desktop information architecture, request investigation, Explorer presets, offline session comparison, data-quality presentation, UI-facing tests, v0.6.0 packaging.
- Excluded: new kernel probes, protocol/schema changes, changing correlation confidence, automatic causal claims without measured evidence.
- Unchanged: capture/preflight/simulator behavior, NDJSON compatibility, CSV export, cached/bounded analysis, diagnostics logging and bundles.
- Forbidden: inventing unavailable latency, selecting one representative file for a multi-file request, unbounded per-frame graph reconstruction.

## Brownfield delta

### ADDED

- REQ-001: The analysis navigation MUST expose `Overview`, `Investigate`, `Explore`, and `Compare`; Diagnostics remains operationally separate.
- REQ-002: Investigate MUST select a bounded recent request and show its pipeline, file origins, slow reason, block evidence, and raw transaction evidence from one cached request view.
- REQ-003: Explore MUST offer named presets and retain advanced X/Y/Group controls, including File group-by.
- REQ-004: Compare MUST load a separate NDJSON baseline without replacing the active session and show absolute and percentage deltas for common summary metrics.
- REQ-005: Overview MUST surface data quality: accepted/rejected records, file attribution coverage, probe coverage, and measurement caveats without treating missing data as zero.

### MODIFIED

- REQ-006: Block Events and File I/O are no longer top-level pages; their useful evidence moves under Investigate.
- REQ-007: Summary becomes decision-oriented Overview while retaining workload distribution and attribution counts.

### UNCHANGED

- NFR-001: Large-session rendering MUST stay bounded: request lists at most 500 entries, file/raw tables virtualized and bounded, Explorer at existing sample/group caps, and per-request graph construction cached.
- CON-001: Loading a comparison session MUST be read-only; cancel or parse failure leaves the current analysis and previous baseline unchanged.
- INV-001: Attribution and confidence labels are evidence-derived. Multiple origins remain multiple and unavailable values are never displayed as measured zero.

## Behavior examples

- SCN-001: Given a loaded session, when the user selects Investigate and a request, then the request list and all detail panels refer to that request.
- SCN-002: Given a baseline is loaded, when Compare opens, then Baseline and Current metrics plus signed deltas are visible; the current session is not replaced.
- SCN-003: Given no baseline or no events, when Compare opens, then an actionable empty state appears and no fabricated delta is shown.
- SCN-004: Given many events, when Explore or Investigate renders repeatedly, then bounded cached views are reused until data generation or selection changes.

BDD Discovery expansion: N/A — the current user explicitly confirmed the ERRC structure and the repository already defines the measurement semantics.

## Contracts and design constraints

- Comparison summary ownership stays in `StudioApp`; `AnalysisEngine` remains the measurement source.
- Explorer presets are value mappings over existing axes/grouping, not a second query engine.
- No new diagnostic event is required: comparison load failures use the existing structured desktop diagnostic path and no new asynchronous or external mutation is introduced.
- Rollback is a source revert to v0.5.1; session data requires no migration.

## Verification

| IDs | Proof |
| --- | --- |
| REQ-001, REQ-006 | Static enum/navigation match and Windows GUI compile |
| REQ-002, NFR-001 | Helper/unit tests plus full workspace tests and UI code inspection |
| REQ-003 | Preset mapping unit tests and GUI compile |
| REQ-004, CON-001 | Comparison delta unit tests, session-load path inspection, GUI compile |
| REQ-005, INV-001 | Data-quality helper tests/inspection and existing protocol tests |

## Definition of Done

- All Must requirements map to current code and exact CI evidence.
- Rustfmt, clippy with warnings denied, workspace tests, Windows GUI check, Android agent, and eBPF object workflows pass.
- v0.6.0 release assets are published only after merge and successful release workflow.
- Actual Windows visual and physical-device behavior remain explicitly marked manual verification.

Release evidence: v0.6.0 targets merge commit `6a3f794fecc0e52be9e315148f22a1d095f517e7`; five assets were published by successful workflow run `33038984740`.
