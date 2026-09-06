# Acceptance status

The full adaptive storage analysis goal is **not complete**. Build, host fixtures,
native rendering, and physical-device acceptance are separate evidence classes.
This ledger supersedes older statements that no phone was available.

## Implemented and exercised

- Compare has independent point/area selections and a responsive right Summary
  panel, with count/time span, Read/Write volume and rates, percentiles, file and
  process candidates, distributions, details, Zoom and Back. Clearing one cohort
  preserves the other. See [Compare behavior](COMPARE_EXPLORER.md).
- Native Compare checks cover three themes, narrow/high-scale layout, selection,
  filtering, and 100,000 requests in each session. The larger comparison used a
  labeled synthetic fixture; it is not evidence from two different phones.
- One non-root Android 16 phone completed the installed application's automatic
  Start/Stop flow using Perfetto, without manually loading a file. FilePath stays
  Unresolved. Unsupported queue measurements stay unavailable.
- Original Perfetto traces can be exported and replayed without modifying the
  original. Host failure fixtures cover transport and recovery boundaries.
- Overview request KPIs and category statistics use the same retained completed
  requests as the graphs, including after retention eviction and filter changes.
  Session totals remain available separately for export. File-operation evidence
  keeps its independent scope and follows request filters where applicable.
- Root preflight also detects shell-accessible Perfetto. If the eBPF collector
  fails before readiness or measurements, it rechecks the same boot and selects
  Perfetto, then device counters when that service cannot start. Host fixtures
  exercise the production transport, including zero-exit without readiness,
  failure after readiness/data, Stop, cancellation during recheck and reboot.
  Initial and updated profiles plus the original failure evidence are preserved.
  This fallback boundary has not been exercised on a physical root phone.
- Perfetto errors after launch first attempt owned-process cleanup and partial
  trace recovery. Missing PID/lifetime output can be rediscovered using the same
  boot, both nonce-owned arguments and stable creation ticks. Uncertain ownership
  leaves an Error with a retryable manifest instead of starting another source.
  Host fixtures cover identity-read failures, missing PID, post-launch nonzero
  exit, normal process-state changes, foreign/ambiguous identities and recovery
  after failed enumeration. These do not establish physical disconnection or a
  real device-side readiness timeout.

The retained-summary regression reproduces 100,001 observed completions with
90,001 remaining in the analysis window. It checks count, separate Read/Write
bytes, percentile and category populations before and after a Write filter, and
asserts that original cumulative totals remain unchanged. A separate existing
file-evidence test verifies that clearing filters restores independent file rows.

## Performance regression and verification

Overview activity graphs now share cached trend data/coordinates and select a
display resolution without changing their original bins or analytical population.
The large-fixture diagnosis and repeatable native input/frame gate are documented
in [Activity plots](ACTIVITY_PLOTS.md). Clicks also populate the chosen interval's
Selection Summary. This component improvement does not close the physical
Stop-to-analysis budget below.

A ten-minute physical capture exposed repeated analysis in the render loop.
The session saved 187,077 completion observations, but Stop to Complete took
88.85 seconds. A QA screenshot timed out while analysis was still running; its
partial request count is not the final session population. The final footer and
raw capture were preserved.

Two changes address this behavior:

1. Device counter graphs project only newly appended snapshots. Loading or
   starting a session discards that projection; reboot/reset intervals and
   disappearing devices do not produce inferred deltas.
2. Stopping/Analyzing displays collection and save progress. Results are built
   after finalization, and a queued capture backlog requests another frame
   immediately. Diagnostics remains accessible while processing.

Reproducible host probes:

```text
cargo test -p android-ebpf-studio --features gui --lib diskstats_performance_tests
cargo test -p android-ebpf-studio --features gui --lib repeated_live_counter_render -- --ignored --nocapture
```

The manual counter probe uses 600 snapshots and 64 devices: debug-build warm
frame median improved from 176 ms to 7.3 ms on the test host. The timing assertion
is intentionally opt-in, not a hardware-independent CI promise. Functional
tests cover repeated frames, appended deltas, boot/reset boundaries, session
replacement, and automatic final results without rebuilding partial batches.

The native QA harness also accepts `ANDROID_EBPF_QA_GESTURE=stream-replay` plus
`ANDROID_EBPF_QA_STREAM_SESSION` and `ANDROID_EBPF_QA_OUTPUT`. It reads a saved
session through the same bounded channel and UI ingestion path without opening
a writer against the original. The 187,077-observation, 203,768,550-byte session
replayed in 1.88 seconds, with one summary rebuild and no rejected observations.
This isolates host ingestion/rendering; it excludes Android trace retrieval and
does not replace a complete physical Stop measurement.

A subsequent physical run lost its Windows QA process during recording, after
approximately 260 seconds. The phone collector remained alive. The native
"Recover from original phone" action then retrieved and analyzed 358,280
completion observations into a new session with integrity OK; the original
NDJSON hash was unchanged. This verifies recovery after an observed host-process
interruption, not physical USB interruption or a successful ten-minute UI soak.
The interruption's origin was not established. At the last recorded UI sample,
the warm frame p95 was 9.61 ms and working set was approximately 223 MiB.

### Post-Stop ingestion and source loss visibility

A later ten-minute non-root capture completed automatically with 329,553
completion observations (99,553 retained details). Stop to analysis took 6.064 s,
so it **failed** the requested five-second budget. Sampled peak working set was
551.3 MiB. The raw trace reported one central-service buffer chunk overwritten
(32,768 bytes), despite kernel loss counters being zero. All timing remained
Unresolved; this is not a loss-free acceptance result.

Analysis now consumes up to 4,000 queued messages per frame while retaining the
4 ms yield boundary. Live recording keeps its existing 1,000-message cap. Native
replay of the same 329,553 observations decreased from 3.000 s to 2.268 s, with
the original hash, retained population and displayed graph/KPI scope unchanged.
The cap had left most of the processing budget unused on inexpensive records,
causing hundreds of unnecessary render cycles. A single expensive record can
still exceed the yield target; this is not a hard real-time guarantee.

```text
node scripts/check-analysis-replay.mjs <release-exe> <capture.ndjson> <new-output-dir> 2300
```

The replay gate checks native completion, nonempty input, rejection count,
preservation of the source, displayed graph/KPI scope and elapsed analysis time.
The 2,300 ms component budget reserves the observed 2.68 s for device Stop,
retrieval and decoding; replay alone does not establish the full Stop budget.
Run on the target host with a representative retained source session. Timing is
an opt-in release check, not a fixed CI hardware promise.

Visible source status now derives service loss, missing counters, lost bundles,
parse errors, truncation, projection limits and failed flushes from the stored
quality evidence. This applies to live capture and reopening older sessions.
Service byte and chunk counters keep their distinct units and are not summed
into kernel event loss. Tests reproduce hidden service loss with zero kernel
loss, preserve unmeasured latency and volume, and check missing-counter and
failure messages. Raw capture contents remain unchanged.

A subsequent ten-minute physical run of the ingestion change completed with
515,961 observations (95,961 retained), 60 successful workload iterations,
5.237 s from Stop to analysis and a sampled 706.3 MiB peak working set. This
**still fails** the five-second requirement. It contained more observations
than the earlier run, so the two wall times are not a controlled improvement
ratio. Stop/pull/decode occupied approximately 2.70 s; analysis/finalization
approximately 2.49 s. The same one-chunk/32,768-byte service overwrite was
observed, with kernel loss zero and all timing Unresolved. The later warning
layout was verified separately on saved actual data in all three themes.

## Outstanding acceptance and limitations

- Fresh root-device verifier/attach and known-file workload validation, a second
  model/kernel, and physical phone replacement/reconnection remain unverified.
- Physical USB interruption and retry have not been validated end to end.
- The complete visible-graph/filter/theme/drilldown matrix is not finished.
  Histogram drilldown now has [a direct request-selection path](LATENCY_DISTRIBUTION.md).
  Full OS accessibility and all system-theme transitions
  require further work or evidence.
- Unsupported Perfetto clocks now have unavailable normalized time across axes,
  filters, temporal aggregation, selection Summary, Compare and exports. Host
  regressions preserve full count/volume and raw evidence for unknown/mixed clocks;
  physical unsupported-clock capture and clock normalization remain unverified.
- [Whole-session FilePath coverage](FILEPATH_COVERAGE.md) now includes observed
  block completions beyond detail retention and preserves late root evidence.
  Root worker memory grows with evidence volume; representative long root
  capture performance and physical known-path accuracy remain unverified.
- A previously observed intermittent native startup access violation has not
  been explained. Forty subsequent launch probes (20 welcome, 20 Compare)
  passed; those repetitions do not establish that the original defect is fixed.
- Ten minutes is a bounded soak, not proof of arbitrary session length or a
  universal five-second processing guarantee. Keep workload size, host load,
  memory, rendering time, and Stop timing together in release evidence.

Physical traces, serial identifiers, screenshots containing process information,
and detailed local run logs are kept outside the public source repository.
