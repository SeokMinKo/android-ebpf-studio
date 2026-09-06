# Latency distribution drilldown

Overview's total-latency histogram now leads to the individual requests behind a
bin or range. Click anywhere in an occupied bin column, or drag horizontally
across bins. The Y axis is an aggregate I/O count; it never filters per-request
latency. Low-count columns remain clickable without requiring subpixel accuracy.

The action preserves process, thread, device, file, confidence and completion-time
filters, applies the latency interval, opens Explore's latency timeline and
selects all matching plotted I/O. The existing Selection Summary includes count,
Read/Write volume and throughput, distributions, latency percentiles, file and
process candidates, and access to I/O details. The active latency range is visible
above the common filters. Clear latency range removes only that condition.
Analysis-view exports record the interval with the other filters.

Expand **Latency bins · keyboard and table access** for per-bin buttons, or choose
From/Through bins and activate Explore selected bins for a range. These standard
controls provide the same operation without a drag or hover gesture. Native QA
checks Enter activation on a focused bin button; this is not a complete screen
reader or OS focus-order certification.

## Measurement rules

Total latency is insert-to-completion when insert exists, otherwise
issue-to-completion. Only valid latency observations enter the distribution.
Measured and unmeasured population counts are shown separately. Missing latency
is never converted to zero. Bin 0 includes 0 and 1 ns; bins 1 through 62 use
[2^x, 2^(x+1)) ns, and bin 63 has no upper bound in the u64 domain. Filters use
integer nanoseconds, inclusive lower and exclusive upper bounds.

Counts and selection use the current retained request cohort, not a sampled
representation of the graph or all historical events evicted from memory.
Original records, path confidence, access classification and missing metrics are
preserved. Removing the latency condition restores the prior non-latency filters.

## Reproducible verification

Unit regressions cover every power-of-two edge, zero/missing latency, the largest
u64 range, reverse drags, empty gaps, other-filter preservation, exact request
identities, percentiles, selected files/processes and clearing the condition.

For a bounded saved trace, run the native regression:

```text
node scripts/check-latency-drilldown.mjs <release-exe> <session.ndjson> <new-output-dir> latency-bar dark
node scripts/check-latency-drilldown.mjs <release-exe> <session.ndjson> <new-output-dir> latency-area contrast
node scripts/check-latency-drilldown.mjs <release-exe> <session.ndjson> <new-output-dir> latency-keyboard light
```

The checker reconstructs request timing independently from source records,
compares exact selected request keys, verifies the source hash and retains a
screenshot. A 5-second gate covers input initiation through ready selection;
automatic scrolling and screenshot capture are separate harness overhead.
The checker requires Node.js 24+ for exact u64 request identities and timestamps.
Fixtures exceeding the retained-count bound are rejected explicitly.
Physical-device capture acceptance remains a separate gate.
