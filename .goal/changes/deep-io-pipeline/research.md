# Research

## Decision questions

1. Which observations are portable enough for a capability-driven Android collector?
2. How should nested/overlapping latency be accounted without double counting?
3. Which UFS/UIC claims are safe at request level?

## Evidence

- [External source] Linux/Android tracefs exposes event `format` metadata at runtime; existing code already parses it instead of hard-coding offsets.
- [External source] Android common kernel defines `ufshcd_command` trace events carrying command tag, LBA, transfer length and operation state. Source: https://android.googlesource.com/kernel/common/+/bce1305c0ece3/include/trace/events/ufs.h
- [External source] F2FS tracepoints are filesystem-specific and vendor/kernel-version dependent. Source: https://docs.kernel.org/filesystems/f2fs.html
- [Repo evidence] Current collector attaches raw syscall and block tracepoints, discovers UFS/F2FS names, but emits no pipeline-stage event.
- [Repo evidence] Block request pointer correlation can be exact; syscall-to-block attribution is currently independent.

## Decisions

- DEC-001: Keep runtime tracepoint-format parsing and capability discovery. Missing optional layers are non-fatal and visible.
- DEC-002: Store stage observations independently from block completions, then correlate by exact ID when available and bounded time/LBA/size heuristics otherwise.
- DEC-003: Calculate additive coverage as interval union clipped to the request window. Do not sum nested stage durations.
- DEC-004: Model UIC as context-only in this slice; UIC management activity is not generally a per-data-command stage.
- DEC-005: First delivery makes the protocol, analysis, simulator and UI complete; device collector attaches only layouts proven safe by runtime format validation. Unsupported variants remain capability-only.

## Residual uncertainty

- Vendor Android kernels rename fields and events; live device verification is required for exact SCSI/UFS attachment coverage.
- Buffered writeback and readahead require a causal DAG beyond one syscall/request timeline and remain deferred.
