# Research — storage-ebpf-mvp / revision 1

## R-001 Android loading model

- Decision: require `adb root` on userdebug/eng for the full collector path.
- Rationale: AOSP documents that Android includes a boot-time BPF loader for programs packaged in `/system/etc/bpf`; an external diagnostic collector therefore cannot assume ordinary app privileges. The user confirmed an `adb root` device.
- Alternative: non-root Perfetto/ftrace mode, excluded from the eBPF MVP to avoid mislabeling.
- Source/freshness: AOSP “Extend the kernel with eBPF”, accessed 2026-08-26; Android developer root/userdebug guidance, accessed 2026-08-26.
- Affects: REQ-002, REQ-003, CON-001.

## R-002 Rust eBPF stack

- Decision: Aya split between a no-std eBPF crate and an Android userspace agent.
- Rationale: official Aya template uses Cargo build scripts to build/include eBPF and documents stable+nightly, rust-src, LLVM and bpf-linker requirements.
- Alternative: libbpf/BCC C collector, rejected because the user requested Rust and it adds a C/Clang/libbpf build surface.
- Source/freshness: aya-rs/aya-template and Aya book, accessed 2026-08-26.
- Affects: DEC-002, NFR-004.

## R-003 Desktop stack

- Decision: eframe/egui plus egui_plot.
- Rationale: official crate API supports native `run_native`; it keeps the Windows application Rust-only and supports live plots.
- Alternative: Tauri, rejected for the MVP because it introduces Node/WebView packaging.
- Source/freshness: docs.rs eframe 0.36.1 and egui_plot 0.37.0, accessed 2026-08-26.
- Affects: DEC-001, REQ-005.
