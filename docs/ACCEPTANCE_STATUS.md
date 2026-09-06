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

## Performance regression and verification

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

## Outstanding acceptance and limitations

- Fresh root-device verifier/attach and known-file workload validation, a second
  model/kernel, and physical phone replacement/reconnection remain unverified.
- Physical USB interruption and retry have not been validated end to end.
- The complete visible-graph/filter/theme/drilldown matrix is not finished.
  Histogram drilldown, full OS accessibility, and all system-theme transitions
  require further work or evidence.
- Unknown Perfetto clocks need a consistent unavailable-time representation
  across plot axes, time filters, and whole-session temporal aggregation.
- Root eBPF attach failure currently falls back to counters; choosing Perfetto
  at that failure boundary still needs implementation and regression coverage.
- Retained-detail FilePath coverage is labeled as such. A whole-session coverage
  denominator beyond the retained analysis window is not yet provided.
- A previously observed intermittent native startup access violation has not
  been explained. Forty subsequent launch probes (20 welcome, 20 Compare)
  passed; those repetitions do not establish that the original defect is fixed.
- Ten minutes is a bounded soak, not proof of arbitrary session length or a
  universal five-second processing guarantee. Keep workload size, host load,
  memory, rendering time, and Stop timing together in release evidence.

Physical traces, serial identifiers, screenshots containing process information,
and detailed local run logs are kept outside the public source repository.
