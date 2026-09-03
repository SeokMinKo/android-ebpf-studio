# Worklog

## 2026-09-03

- User confirmed implementation with “Go”. Classified L3/DURABLE/DESIGN_FIRST because kernel ABI, protocol, agent, eBPF verifier, compatibility, and device gates cross multiple components.
- Baseline: clean `main` at `3a70f1b`; work branch `feature/exact-file-block-attribution`.
- Repository inspection confirmed protocol/graph groundwork is present and exact VFS/bio/file-to-request probes remain the open gap.
- Environment gap at preflight: pinned Rust toolchain was not initially installed and the target Android phone was not connected. Rust 1.98, nightly, rust-src, bpf-linker, and the Android Rust target were subsequently installed; the phone-only gate remains open.
- TSK-001 completed with RED/GREEN graph and schema tests. Exact raw origins suppress the unique time/task heuristic and retain 0..N origins.
- TSK-002 completed with RED/GREEN ABI decode and BTF-layout parser tests. Raw object addresses are hashed by the agent before protocol serialization.
- TSK-003 host work completed. The eBPF adapter uses runtime BTF field offsets, VFS/writeback-to-bio maps, `blk_mq_bio_to_request`, and success-only `tp_btf/block_bio_frontmerge|backmerge`; origin fan-in is bounded and overflow is explicit.
- TSK-004 completed with fallback characterization: exact attribution is enabled only after every essential typed hook attaches, while mandatory block tracepoints remain active on failure.
- TSK-005 completed: workspace tests, formatting, clippy with warnings denied, eBPF build/ELF-section inspection, Android aarch64 check, and diff whitespace check passed.
- Final audit added a regression for live cache invalidation and made BTF preflight failures explicit in the capability plan; the full locked host gate chain remained green.
- TSK-006 remains device-blocked. A rooted userdebug board is required for verifier/load/attach and direct-I/O, buffered-writeback, and merge workload acceptance.
- User requested a Git handoff for continuation in another environment. TSK-007 added `docs/EXACT_FILE_ATTRIBUTION_HANDOFF.md`, linked it from README, and preserved TSK-006 as the only unverified acceptance gate.
