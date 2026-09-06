# I/O analysis contract

User clarification, 2026-09-06: Summary is the existing right-hand Explore inspector, linked to the main Trend graph, NOT a separate catalogue/page of aggregate graphs. Main LBA Footprint -> LBA histogram/violin and per-address repeated Read/Write counts. Chunk, Latency and QD trends -> matching histogram and percentiles. Same full filtered cohort or explicit graph selection; changing graph, filters or selection refreshes Summary. Existing Overview is not the requested Summary panel.

This clarification supersedes the topology interpretation of the attached objective. Remaining objective requirements (uPAS coverage, grouped footprints, bandwidth, common filters, capture completeness, testing, performance, backed-up installation and native launch) still apply.

Baseline: source HEAD 743a3488117cd02df4cc66f79d4e19e82adf3e75, clean worktree. Installed BUILD-MANIFEST.json has the same source commit/tree; unlike the older description, current manifest contains no source directory field. Worktree branch: feat/upas-io-analysis. uPAS is read-only. 43 selectable entries extracted directly from GraphFigure, including non-default selections; docs/UPAS_FEATURE_MATRIX.json is the evolving inventory, not a completion claim.

Numeric rules: nearest-rank exact percentiles of valid retained samples, missing values excluded with explicit counts; histograms use [lower, upper) except inclusive final upper edge. Plot downsampling never changes the summary population. LBA = 512-byte sectors independent of filesystem block size. Duplicate address counts use half-open sector intervals, split by device, independently count Read and Write overlaps, and never add candidate-file duplicate rows to global bytes.
