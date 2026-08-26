# Worklog (append only)

| Sequence/time | Spec IDs | Task/Test ID | Exact command/check | Exit/status | Raw summary | Evidence scope | Artifact revision |
| --- | --- | --- | --- | --- | --- | --- | --- |
| S1 | baseline | TST-106 | `cargo test --workspace` | ENV / 127 | `cargo: command not found` | No executable baseline; source/history inspection only | `1f1ab8f` |
| S2 | baseline | TST-106 | `cargo test --workspace` | 0 | workspace baseline passed: agent 2, protocol 8, desktop 3 tests | Baseline after Rust 1.98 install | `1f1ab8f` |
| S3 | RULE-101/102, REQ-102/103/105 | TST-101..104 | `cargo test -p android-ebpf-protocol` | 101 | expected missing symbols/fields for size, insert, file, utilization | RED-VALID for new behaviors | working tree |
| S4 | RULE-101/102, REQ-102/103/105 | TST-101..104 | `cargo test -p android-ebpf-protocol` | 0 | protocol tests passed: aggregation 1, classification 4, correlation 3, pipeline 3, session 3 | GREEN | working tree |
| S5 | all local | TST-101..106 | `cargo test --workspace` | 0 | agent 3, protocol 14, desktop 3 tests passed | Full local regression | working tree |
| S6 | all local | TST-106 | `cargo clippy --workspace --all-targets -- -D warnings` | 0 | finished successfully | Static analysis | working tree |
| S7 | REQ-104/105 | TST-105 | `cargo clippy -p android-ebpf-studio --all-targets --features gui -- -D warnings` | 0 | GUI compiled without warnings | Linux GUI compile boundary | working tree |
| S8 | REQ-102/103 | TST-104 | `cargo +nightly build --manifest-path crates/android-ebpf/Cargo.toml --target bpfel-unknown-none -Z build-std=core --release` | 0 | optimized eBPF object built | eBPF compile boundary; no phone verifier | working tree |
| S9 | all local | TST-106 | `cargo fmt --all -- --check` and eBPF manifest fmt check | 0 | no format diff | Formatting | working tree |
