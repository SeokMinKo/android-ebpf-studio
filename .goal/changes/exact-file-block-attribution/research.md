# Research record

## Repository baseline

- Baseline `3a70f1b` already has stable `FileIdentity`/`PathSnapshot`, graph nodes/edges, multi-origin graph queries, syscall `/proc/<pid>/fd` fallback, block tracepoint format discovery, and capability reporting.
- The current graph creates `Probable`/`ProbableAsync` file edges from a unique time/task/op/size candidate. It has no directly emitted file-to-request origin record.
- The current eBPF object contains tracepoints only. Capability text lists fentry candidates but marks deep VFS/bio adapters unavailable.
- Existing change `deep-io-attribution-pipeline` records this missing implementation as open high-severity `GAP-005`.

## Kernel/API facts used by the design

- Generic block tracepoints expose request/bio objects at typed tracepoint definitions, so `tp_btf` can preserve object identity where the target kernel publishes BTF.
- Linux `bpf_d_path` is allow-listed by attach context on common Android kernels; it is not a general helper for arbitrary block tracepoints. Path capture therefore belongs at an allowed upper-layer file hook or in userspace by stable identity.
- Bio/request merging is N:1; a request cannot be modeled as having exactly one file.
- F2FS tracepoints can expose inode/folio/block/bio context on kernels that retain those tracepoints, but availability is vendor/config dependent.

Primary references:

- https://github.com/torvalds/linux/blob/master/include/trace/events/block.h
- https://github.com/torvalds/linux/blob/master/include/trace/events/f2fs.h
- https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/kernel/trace/bpf_trace.c
- https://docs.kernel.org/bpf/btf.html

## Decision

Use typed BTF probes as an optional exact-attribution adapter and keep generic tracepoints mandatory. Capture numeric identity and bounded object relationships in kernel space; resolve/display path snapshots separately. Never walk dentries from the request hot path.
