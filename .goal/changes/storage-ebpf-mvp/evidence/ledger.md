# Evidence ledger

| Sequence/time | Spec IDs | Task/Test ID | Exact command/check | Exit/status | Raw summary | Evidence scope | Artifact revision |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 0001 | NFR-004 | ENV | `rustc --version` | 127 | `/bin/bash: rustc: command not found` | local compile environment unavailable | spec@1 |
| 0002 | REQ-004, CON-002 | TST-001 | `cargo test -p android-ebpf-protocol --test correlation` before implementation | 101 | unresolved protocol imports | RED: correlation API absent | spec@1 |
| 0003 | REQ-006 | TST-002 | `cargo test -p android-ebpf-protocol --test classification` before implementation | 101 | unresolved classifier imports | RED: classifier absent | spec@1 |
| 0004 | REQ-005 | TST-003 | `cargo test -p android-ebpf-protocol --test aggregation` before implementation | 101 | unresolved analysis imports | RED: aggregator absent | spec@1 |
| 0005 | REQ-007, REQ-008, NFR-002 | TST-004 | `cargo test -p android-ebpf-protocol --test session` before implementation | 101 | unresolved session imports | RED: session codec absent | spec@1 |
| 0006 | REQ-001, NFR-003 | TST-005 | `cargo test -p android-ebpf-studio --test adb` before implementation | 101 | missing `adb` module | RED: transport absent | spec@1 |
| 0007 | REQ-001..REQ-010 | TSK-001..TSK-004 | `cargo fmt --all -- --check && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo clippy -p android-ebpf-studio --all-targets --features gui -- -D warnings` | 0 | format passed; 13 tests passed; both clippy scopes passed | local host convergence | spec@1 |
| 0008 | REQ-002, REQ-003, REQ-009 | TSK-004 | `cargo +nightly build --manifest-path crates/android-ebpf/Cargo.toml --target bpfel-unknown-none -Z build-std=core --release` | 0 | optimized eBPF build passed | eBPF compiler/linker | spec@1 |
| 0009 | REQ-002, REQ-003, REQ-009 | TSK-004 | `file .../android-storage-ebpf && readelf -S .../android-storage-ebpf` | 0 | ELF 64-bit relocatable eBPF; tracepoint/license/maps sections present | static eBPF artifact structure | spec@1 |
| 0010 | NFR-004 | TSK-005 | secure GitHub browser auth + fresh visible DOM | blocked | manual takeover returned; login form remained visible | remote repository creation unavailable | spec@1 |
| 0011 | REQ-001, REQ-002, REQ-003, NFR-003 | TSK-002/TST-005 | `cargo test --workspace` | 0 | 3 ADB tests passed within 13-test suite | selected-serial transport working set | spec@1 |
| 0012 | REQ-005, REQ-010, NFR-001 | TSK-003 | `cargo clippy -p android-ebpf-studio --all-targets --features gui -- -D warnings` | 0 | GUI-feature targets compiled without warnings | desktop GUI/static simulator path | spec@1 |
| 0013 | REQ-004, REQ-005, REQ-006, REQ-007, REQ-008, NFR-002, CON-002, INV-001 | TSK-001 | `cargo test -p android-ebpf-protocol` | 0 | 8 protocol integration tests passed | protocol behavior completion | spec@1 |
| 0014 | REQ-001, REQ-002, REQ-003, NFR-003, CON-001 | TSK-002/TST-005 | `cargo test -p android-ebpf-studio --test adb` | 0 | 3 ADB tests passed | selected-serial ADB behavior completion | spec@1 |
| 0015 | REQ-001, REQ-002, REQ-003, NFR-003, CON-001 | TSK-002/TST-005 | `cargo clippy --workspace --all-targets -- -D warnings` | 0 | workspace clippy passed | ADB refactor convergence | spec@1 |
| 0016 | REQ-004, REQ-005, REQ-006, REQ-007, REQ-008, NFR-002, CON-002, INV-001 | TSK-001/TST-001 | `cargo fmt --all -- --check` | 0 | workspace formatting passed | protocol refactor convergence | spec@1 |
| 0017 | NFR-004 | TSK-005 | GitHub commit fetch for `0f032e93d087460ed130cdd3ef78b13894d6352c` | 0 | README and 43-file source commit visible on public `main` | repository publication | spec@1 |
| 0018 | NFR-004 | TSK-005 | GitHub Actions run `32924015976` | 0 | Success; rust-tests, windows-gui, ebpf-object, android-agent all passed | remote cross-platform convergence | spec@1 |
