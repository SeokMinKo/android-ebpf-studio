# Evidence ledger

| Sequence/time | Spec IDs | Task/Test ID | Exact command/check | Exit/status | Raw summary | Evidence scope | Artifact revision |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 2026-08-26T00:01:00+09:00 | baseline | TSK-001 | `cargo test -p android-ebpf-protocol` | NOT RUN / ENV | `/bin/bash: cargo: command not found` | No local baseline test claim | spec sha `9c006543...` |
| 2026-08-26T20:51:00+09:00 | REQ-001/2/3, NFR-001/2 | TST-001/2/3/7 | `cargo test -p android-ebpf-protocol` | 0 | 18 integration tests passed; 0 failed | Protocol behavior and compatibility | spec@2 |
| 2026-08-26T20:53:00+09:00 | REQ-005/7 | TST-006/8 | `cargo check -p android-ebpf-studio --features gui` | 0 | Finished dev profile | Linux GUI compile boundary | spec@2 |
| 2026-08-26T20:54:00+09:00 | all implemented | TSK-001..006 | `cargo clippy --workspace --all-targets -- -D warnings` | 0 | Finished dev profile | Workspace static analysis | spec@2 |
| 2026-08-26T20:55:00+09:00 | all implemented | TSK-001..006 | `cargo test --workspace` | 0 | All listed workspace unit/integration/doc tests passed | Workspace regression | spec@2 |
