# Whole-session FilePath coverage

Overview now separates whole-session coverage from the filtered, retained detail
window. The whole-session result is produced automatically by the persistence
worker after Stop and by the replay worker when a saved session is opened.
Selecting a time window, filtering or selecting a Compare cohort does not change
the source result. CSV summary and analysis-view metadata include it.

## Denominator and evidence

- Percentages are by observed **block completion record count**, including
  unmatched completions as Unresolved. Pending issues, lost events and suppressed
  detail are outside this population. Capture diagnostics remain authoritative
  for those omissions; their volume or FilePaths are not inferred.
- Known bytes are the sum of reported request sizes, not a measurement of physical
  media transfers. Unmatched completion bytes are unavailable,
  not zero. Multi-origin records overlap confidence rows; they count once in the
  denominator, regardless of candidate count.
- Exact requires actual nonempty paths and Exact causal evidence for every origin.
  Probable includes asynchronous probable origins. Missing paths, context-only
  candidates and a collector-reported incomplete origin set remain Unresolved.
  An Exact inode alone does not establish an Exact FilePath.
- Unresolved reasons are disjoint: no origin, missing path, context-only evidence,
  incomplete origin set, nonjoinable source observation, or unmatched completion.
  Existing identity-edge attribution counters remain compatible and explicitly
  labeled as retained-detail identity statistics in CSV.

## Retention and work ownership

The coverage worker preserves root request lifetimes and file/graph evidence until
the source ends, then evaluates each request using the same transaction model as
the detail view. It therefore includes late evidence for requests older than the
100,000-request detail window. Reused request IDs keep their original lifetime
windows. A new capture/loaded source replaces the report; no global device cache
is used. Raw session data remains the reproducible source of truth.

Perfetto observations cannot join root request IDs. They reduce directly to
Unresolved count/volume counters without retaining their large raw evidence in
the coverage worker. Root coverage memory grows with request and evidence count;
it is not a constant-memory algorithm. Final graph caches remain bounded, and
the temporary worker data is released after reporting. Long root captures still
require memory and end-to-end performance acceptance on representative devices.
No universal five-second or arbitrary-session-length guarantee is claimed.

## Regression checks

```text
cargo test -p android-ebpf-protocol --test filepath_coverage
cargo test -p android-ebpf-studio --test reanalysis
cargo test -p android-ebpf-studio --test perfetto_projection
node scripts/check-filepath-coverage.mjs <release-exe> <session.ndjson> <new-output-dir> light
```

Host tests cover both request and graph retention overflow at 100,001 completions,
late origins, identity without path, mixed candidates, incomplete sets, reused
request lifetimes, cancellation, persistence/reopen/window/export equivalence,
and more than 100,000 nonroot observations. The native script independently
counts raw completion records, checks the unresolved partition, validates known
Perfetto volume, preserves the source hash, and records coverage/replay time.
An optional JSON oracle supports labeled known-path fixtures. Expanded disclosure
in this script is a static QA preset; it does not prove a pointer/keyboard toggle.

Native saved-data evidence is separate from root known-file workloads, phone
replacement, physical disconnection and end-to-end Stop measurements. See the
[acceptance ledger](ACCEPTANCE_STATUS.md) for those outstanding gates.
