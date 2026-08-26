# Design — storage-ebpf-mvp / revision 1

## Architecture

```text
Windows desktop
  UI + analysis + session writer
          |
      ADB transport
          |
Android arm64 agent (root)
  capability probe + Aya loader
          |
 eBPF tracepoints + ring buffer
          |
 Android block/UFS kernel events
```

The eBPF side emits minimal fixed-layout kernel records. The Android agent enriches them, correlates issue/complete when needed, converts monotonic timestamps, and writes one NDJSON record per stdout line. Windows treats stdout as a versioned protocol and stderr as bounded diagnostics.

## Responsibility boundaries

- `android-ebpf-protocol`: schema, parser, request correlation, sequential/random classifier and aggregates; platform-independent and fully unit-tested.
- `android-ebpf-desktop`: GUI, ADB commands, bounded ingestion, session storage/export and simulator.
- `android-ebpf-agent`: capability scan, Aya program loading/attachment, ring-buffer drain and NDJSON output; Linux/Android only.
- `android-ebpf`: no-std tracepoint programs and POD kernel record.

## Storage event model

`BlockIssue` fields: timestamp, request ID, device major/minor, sector, sectors, bytes, read/write/discard/flush, PID/TID/CPU/process, optional command tag and UFS LUN.

`BlockComplete` carries the matching request identity, completion status and optional hardware fields. The protocol also supports `FsRead`, `FsWrite`, `FsSync`, `UfsCommandStart`, and `UfsCommandComplete`; unsupported probes are omitted from capabilities rather than emitting empty fake data.

## Compatibility strategy

1. Preflight enumerates tracefs event paths and `/sys/kernel/btf/vmlinux`.
2. Profiles are selected by supported fields, not Android marketing model.
3. Generic block events are mandatory for full mode.
4. Vendor UFS events are allow-listed from discovered formats and remain optional.
5. Protocol readers ignore unknown JSON fields and reject unknown record types with a counted diagnostic.

## Test strategy

Inside-out: prove correlation, classification and aggregation with deterministic events; then prove ADB argument construction; finally exercise the UI through a simulated event source. Real eBPF verifier/device evidence is a separate hardware integration boundary.

## Abstraction evidence

`EventSource` is justified by two real variants: ADB collector and deterministic simulator. `AdbRunner` isolates external process execution for argument/diagnostic tests. Analysis types remain concrete.
