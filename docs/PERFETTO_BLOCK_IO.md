# Non-root Perfetto block I/O

Status: native decoder, owned Android transport, automatic non-root preflight,
desktop Start/Stop integration and protocol v6 observations are implemented in
source. Actual native GUI Start/Stop acceptance passed on one non-root phone;
offline native UI verification also uses a captured real trace. See the bounded
evidence below; deployment status belongs to the distribution build manifest.

## Measurement model

`perfetto.rs` streams bounded protobuf packets and projects block request issue,
complete, insert and requeue events. Cross-CPU packets are sorted by timestamp.
Raw `capture.pftrace` remains available for independent analysis and re-import.
Trace-local record IDs identify evidence records; they are never kernel request
IDs. Raw device encoding is retained; major/minor decoding is the inverse of
Perfetto CpuReader's `TranslateBlockDeviceIDToUserspace` (Linux userspace makedev).
It must not be interpreted as the kernel's major-shift-20 representation.

Every decoded completion remains in the block observation population, including
unmatched, ambiguous and partial completions. Completion bytes are the tracepoint
sector count multiplied by 512. Layered devices can represent the same physical
work more than once: per-device filtering is necessary and summing all device
layers is not application I/O volume.

Unique observed device/range/direction issue candidates yield **Probable**
issue-to-completion timing. Repeated or overlapping outstanding requests,
partial completions, requeue, equal timestamps, unsupported clock domains,
explicit loss, corruption or projection limits suppress timing and issuer
assignment. Multiple candidates remain attached to the completion. Missing
latency and queue wait are `None`, never a fabricated zero. Request insert is
optional and queue wait requires a unique, earlier insert candidate.

The tracepoint PID is a **TID**. Completion context is not used as the issuer.
Raw process/thread snapshots and process age metadata are preserved. The latest
dated snapshot at or before issue provides a candidate TGID/name only if process
age is compatible. Future, undated or contradictory equal-time snapshots cannot
establish an issuer. Completion CPU is not used as issue CPU. Unknown PID/TID,
CPU and completion status remain optional, distinguishable from measured zero.
FilePath is always **Unresolved** for this block-only source. Neither the command
name nor a nearby file operation establishes a file association.

## Quality and recovery

### Automatic fallback after root collector startup failure

Preflight checks shell-accessible Perfetto even when root, ABI and readable
tracepoints suggest eBPF can start. A verifier/deployment/startup failure before
readiness and before measurements triggers fresh detection for the same serial.
The boot must still match. The failed collector is stopped before another source
is started. Perfetto is preferred to device counters; counters remain available
if the service is absent or rejects startup. Block-only FilePath stays Unresolved.

The first profile is preserved as `device-profile-before-fallback.json` and the
updated `device-profile.json` includes `ebpf_start_error`. The original failure
and selected fallback are also recorded in a session SourceInfo record. A new
Start performs a fresh preflight rather than persisting that failure across runs.
Already emitted measurements, readiness followed by failure, a changed boot or
cancellation prevent an unrelated collector from continuing the same session.
Exit code zero without readiness is not treated as successful capture.

Host-only fake ADB tests exercise these transitions through the production
capture code and owned Perfetto transport. They are not physical root acceptance.

### Perfetto launch failures and partial recovery

A failed `--background-wait` call can follow a successful background fork; its
exit status alone does not prove that no collector is running. The desktop saves
any returned PID even on a nonzero exit. If launch/readiness fails, it first
identifies and stops its own capture and projects retrieved observations into the
normal session analysis. The result remains Error, with the startup reason,
quality evidence, raw trace and recovery manifest preserved. It does not silently
replace partially collected block I/O with device counters.

If PID or lifetime output was lost, recovery checks the original boot and looks
for a unique Perfetto process containing both exact nonce-scoped config and trace
arguments. Creation ticks must stay stable across identification; normal changes
between running and sleeping states do not change process ownership. Foreign or
ambiguous processes are never signalled. Failed enumeration/connectivity leaves
an explicit recovery error; retry uses the saved manifest after reconnection.
Counters start only when no owned process or accessible trace remains.

Host regressions cover transient identity reads, missing PID output, nonzero exit
after launch, changing process state, foreign commands, ambiguous matches and a
failed enumeration followed by successful recovery. They do not simulate physical
USB removal. Background semantics: [Perfetto CLI reference](https://perfetto.dev/docs/reference/perfetto-cli).

### Saved source quality

The decoder preserves ftrace lost-bundle flags, parse errors, unavailable and
failed events, kernel start/end counters, service loss counters and final-flush
status. Missing counter pairs and counter resets are unknown rather than zero.
Packet size is bounded to 16 MiB, projected block events to 2 million, metadata
to 200,000 entries and pending candidates per device/direction to 4,096. Limits
are explicit and do not remove the raw trace file. Malformed tails preserve
complete preceding packets and report truncation.

`perfetto_capture.rs` starts a finite `--background-wait` session with a unique
config and output path. The owner manifest records serial, boot ID, PID and
process start ticks. Stop checks the process lifetime and exact owned arguments
before signalling, waits for termination and retrieves the raw trace. Failed
retrieval leaves the manifest and existing source intact; recovery validates
owned paths and keeps earlier downloads as backups. The default caller must
expose the finite duration and 256 MiB file limit.

The Session menu offers **Recover from original phone**, **Reanalyze saved raw
trace**, and **Export Perfetto raw trace** when the corresponding files exist
beside the session. Error states surface the two recovery actions directly.
Recovery writes a new `capture-recovered-<uuid>.ndjson`; original NDJSON is never
overwritten. Phone recovery binds to the manifest's serial, independently of the
currently selected phone. After a reboot it only pulls the nonce-scoped trace
and never signals the old PID. Missing process lifetime evidence prevents unsafe
signalling. Local raw reanalysis works without a phone and preserves truncated
prefixes with explicit quality evidence. Raw export rejects existing destination
files, including source aliases; source files are untouched on copy failure.
New device recordings keep `capture.ndjson`, device profile, logs and the
`perfetto/` subdirectory together in a unique session directory. This makes raw
export and recovery locate the same run without searching another session's log
tree. Existing standalone NDJSON sessions remain readable.

### Stage timing probe

```text
cargo run --release -p android-ebpf-studio --example perfetto_benchmark -- <saved-capture.pftrace>
```

This read-only probe reports decoder, correlation, index, projection and
projection-plus-serialization timings. Serialization repeats projection, so do
not sum the two projection measurements. The benchmark excludes ADB operations,
GUI ingestion, disk writes and fsync; native Start/Stop remains the end-to-end
acceptance gate. A 45,147,958-byte real trace with 515,961 completion observations
measured approximately 492 ms decode, 288 ms correlation, 110 ms index and
384 ms projection plus serialization to a sink on the recorded Windows host.
These figures identify component costs, not a five-second capture guarantee.

## Evidence recorded on 2026-09-06

- Actual non-root Samsung SM-F966N; Perfetto v51.2; one phone only.
- Native GUI Start -> Recording -> Stop -> automatic Overview passed without
  manually loading a file: 1,052 raw block records / 526 completions, all with
  probable timing and unresolved FilePath. Stop input to completed analysis was
  1.984 s. The app saved the session and its raw trace together. The two-file
  workload below also passed during this GUI recording. These measurements
  include background traffic and do not establish exact request identity.
- New Rust transport: ready in 1.069 s; recorded for 5 s; Stop, pull and decode
  completed in 1.264 s. 7,283 block events / 3,641 completions; 3,629 probable
  timings and 12 unresolved timings. These are observed candidate matches, not
  ground-truth request identity validation.
- Two unique 4 MiB test files: buffered writes, fsync and 4 MiB verified Direct
  Read per file all succeeded. Background and layered-device traffic is also in
  the trace; total trace bytes must not be claimed as the workload's exact bytes.
- This device reports `block_rq_insert` and `block_rq_requeue` as unknown.
  Queue wait is unavailable. No FilePath attribution is claimed.
- Kernel loss counters and available service counters were zero, no malformed
  packets or lost bundles were reported. Final-flush enum was unspecified (0);
  successful final flush is not asserted from that field.
- Host regressions cover CPU packet ordering, duplicate ranges, partial
  completion, requeue, missing timing, malformed tails, kernel resets, service
  loss, non-default clocks, PID lifetime parsing and failed-retrieval preservation.
- Synthetic 100,000 completed I/O with reversed CPU packet order: native release
  decode and candidate analysis 140 ms; whole example process 295 ms, 6.93 MB
  input. This is a decoder benchmark, not GUI rendering or long-session proof.

Private raw traces, process names, serials and screenshots remain in local
acceptance artifacts; they are not committed to the public repository.

## Remaining integration requirements

Implemented source behavior: non-root preflight collects available metadata and
probes `linux.ftrace`; Start selects Perfetto when full root tracing is unavailable.
Recording reports elapsed time and trace bytes with separately labelled live
device counters. Stop waits, retrieves, decodes and emits observations into the
normal session writer and analysis engine. Source quality survives session reload.
The Overview shows completed I/O after Stop even if live device counters exist.
Selections retain missing-timing volume and display valid/total timing samples;
Compare exports nullable process IDs and timing values. CSV percentiles are blank
when unavailable. File/kernel graph joins cannot use trace-local record numbers.

Offline UI evidence: Overview, Investigate, five Explore axis presets including
unavailable queue/layer axes, area selection with Zoom/Back, selected Files and
Processes, and Compare area/Processes. The actual trace has 3,641 completions;
12 have no timing. The LBA population includes all 3,641, while the latency graph
has 3,629 plottable requests. A comparison of the same trace verifies interaction,
not a real before/after performance difference. Light, Dark and High Contrast
were exercised; this is not every theme/axis/filter combination.

Still required:
1. Actual-device interrupted capture/resume validation, non-root capability
   fallback validation and full performance/graph matrix. Host recovery fixtures
   cover reboot, PID reuse and failed pull; native GUI local recovery and raw
   export passed with the actual 3,641-completion trace. These do not prove a
   physical disconnect/reconnect flow. Export QA supplies the destination through
   an explicit test-only hook; the OS Save dialog is outside that check.
2. Windows packaging, install/launch verification and authorized Git commit,
   push and merge after integration and regression checks.

## Primary schema and lifecycle references

- [Block event schema](https://github.com/google/perfetto/blob/main/protos/perfetto/trace/ftrace/block.proto)
- [Ftrace bundle clocks and loss](https://github.com/google/perfetto/blob/main/protos/perfetto/trace/ftrace/ftrace_event_bundle.proto)
- [Ftrace statistics](https://github.com/google/perfetto/blob/main/protos/perfetto/trace/ftrace/ftrace_stats.proto)
- [Service statistics](https://github.com/google/perfetto/blob/main/protos/perfetto/common/trace_stats.proto)
- [Process and thread metadata](https://github.com/google/perfetto/blob/main/protos/perfetto/trace/ps/process_tree.proto)
- [Background capture and flush](https://perfetto.dev/docs/learning-more/tracing-in-background)
- [Perfetto block device translation](https://github.com/google/perfetto/blob/main/src/traced/probes/ftrace/cpu_reader.h)
