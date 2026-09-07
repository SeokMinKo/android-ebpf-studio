# Plot sampling preserves measured shape

The previous index-only sample could omit an interior LBA peak: 2,001 Read requests with a penultimate 1,024 MB address produced no displayed 1,024 MB point. The native dense physical session also lost its maximum address (45,619.994624 MB, shown maximum 45,619.978240 MB). Both failures are retained as acceptance evidence.

Explore and Compare now measure each eligible request before sampling, including graph-derived axes. Sampling is stratified by rendered category and Read/Write operation. Each chronological bucket retains first/last and minima/maxima on both axes. Additional points retain the two sides of sparse coordinate gaps, defined as greater than both eight median positive spacings and two target sampling cells. Remaining capacity is distributed across the remaining raw observations. The point target is soft when required feature boundaries exceed it. No averaged or interpolated coordinates are created.

Missing axis measurements are counted across the full cohort, separately from sampling. Selection, KPI and exports continue to use their full filtered cohorts. Source records are not changed.

Regressions include the penultimate maximum, physical endpoints, sparse gap boundaries, and alternating Read/Write categories. The 2,001-request synthetic NDJSON is a regression fixture, not physical FilePath evidence. Full-coordinate measurement increases preprocessing work; native dense timing must be reported rather than assuming the earlier sampled-only performance still applies.
