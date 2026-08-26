# Tasks — storage-ebpf-mvp / revision 1

| ID | Spec IDs | Dependency | Output / first RED | Evidence / DoD | Status |
| --- | --- | --- | --- | --- | --- |
| TSK-001 | REQ-004, REQ-006, REQ-007, REQ-008, NFR-002 | none | protocol+analysis crate; tests initially fail because behavior is absent | `cargo test -p android-ebpf-protocol` | completed |
| TSK-002 | REQ-001, REQ-002, REQ-003, NFR-003 | TSK-001 | validated ADB orchestration; command construction tests | desktop unit tests | completed |
| TSK-003 | REQ-005, REQ-010, NFR-001 | TSK-001, TSK-002 | live GUI and simulator | GUI-feature compile + bounded simulator path | completed |
| TSK-004 | REQ-002, REQ-003, REQ-009 | TSK-001 | Android agent/eBPF crates and build/deploy scripts | Linux/BPF compile and real-device checklist | completed; hardware run blocked |
| TSK-005 | all | TSK-001..004 | docs, CI, convergence and GitHub repository | CI and repository URL | blocked: GitHub browser login incomplete |

Single implementation stream; no concurrent file leases. Forbidden actions: phone mutation beyond `/data/local/tmp/android-ebpf-studio`, SELinux policy change, repository publication as public without a later user decision.

## Behavior Test List

| ID | Spec IDs | Behavior | Kind | Boundary | Expected RED | Status |
| --- | --- | --- | --- | --- | --- | --- |
| TST-001 | REQ-004, CON-002 | completion computes latency and removes one pending request | NEW_BEHAVIOR | protocol API | unresolved types/functions | PASSED |
| TST-002 | REQ-006 | adjacent sectors classify sequential; jumps classify random | NEW_BEHAVIOR | classifier API | classifier absent | PASSED |
| TST-003 | REQ-005 | buckets compute throughput/IOPS/latency percentiles | NEW_BEHAVIOR | aggregate API | aggregator absent | PASSED |
| TST-004 | REQ-007, REQ-008, NFR-002 | valid records survive malformed lines with exact reject count | NEW_BEHAVIOR | session reader | reader absent | PASSED |
| TST-005 | REQ-001, NFR-003 | ADB parser and selected-serial command are deterministic | NEW_BEHAVIOR | desktop transport | transport absent | PASSED |

Observability: OBS-001 and OBS-002 from Spec. Working suite: targeted package test. Commit suite: `cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`.
