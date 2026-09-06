# Observed queue depth

The app distinguishes two observations across **all captured block devices**:

- `queue_depth_at_issue`: correlated requests in flight immediately after this
  issue, including this request. The Queue depth vs latency preset uses this.
- `queue_depth_after`: correlated requests remaining after this completion. This
  older field remains available as the explicitly named after-completion axis.

These are observed host-correlation counts, not a hardware queue-depth gauge.
Device-mapper and physical rows can represent the same underlying I/O. Lost or
suppressed events, ambiguous IDs and correlator expiry can undercount requests.
Filtering by device/process/file preserves each original count; it does not
recompute concurrency within the selected subset.

Overview's **Max observed depth** is the maximum issue-time value among retained,
filtered completed requests. It displays the measured/total request population.
Whole-source cumulative summaries can also include issue observations for requests
that never completed. CSV exports state the definition and measured count. Time
buckets record depth at issue timestamps, while bytes, completion counts and
latency retain their completion-time basis. An issue-only bucket has no measured
completion latency.

The old retained-summary path took the maximum of after-completion values, so a
serial request's peak became zero. A later low-depth issue also overwrote earlier
peaks in the same time bucket. Issue-time observations are now stored with the
request and maxima are accumulated monotonically within each scope.

## Compatibility and absence

The issue-time field is optional on projected completion records. Older readers
can ignore it; older projected records deserialize without it. Raw issue/complete
sessions acquire the value when replayed. A projected record without the new
field does not infer a value from completion depth or latency. Current Perfetto
projection leaves both counts unmeasured and omits the new null field from raw
serialization. This avoids adding per-record size to large non-root traces.

Investigate's raw block evidence shows both values. Explore and Compare expose
the same explicit axis definitions and original request context. Unknown values
are not drawn as zero; their requests remain available on measured axes and in
the detail table.

## Validation

```text
cargo test -p android-ebpf-protocol --test queue_depth
node scripts/check-queue-depth.mjs <release-exe> <paired-source> <new-output-dir> overview light
node scripts/check-queue-depth.mjs <release-exe> <paired-source> <new-output-dir> explore dark read
node scripts/check-queue-depth.mjs <release-exe> <paired-source> <new-output-dir> compare contrast all point
```

The Node.js 24+ native gate independently counts in-flight raw requests and
compares every retained sample, plotted coordinate, peak and measured count.
Point mode verifies a one-request Summary and unchanged selection on the other
comparison side. It uses a bounded unambiguous source of up to 12,000 I/O; large
render/Stop timing has separate gates. Compare with the same source checks
projection fidelity, not heterogeneous-device or performance-comparison validity.

Protocol regressions cover serial/overlapping requests, later low-depth issues,
filter and time-window replay, distinct issue/completion buckets, cross-device
context, legacy/mixed projections and detail eviction. Desktop checks cover both
axes, missing measurements, persisted replay and CSV metadata. The archival root
trace has 184 measured I/O with an independently reconstructed peak of 10. A
64-I/O Perfetto fixture retains all requests with no depth measurements. These
saved-data checks are distinct from fresh physical-device acceptance.
