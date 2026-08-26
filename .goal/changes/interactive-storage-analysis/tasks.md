# Tasks and behavior test list

| ID | Spec | Behavior / output | Cycle | Expected RED | Status |
| --- | --- | --- | --- | --- | --- |
| TST-101 / TSK-101 | RULE-101, RULE-102 | exact continuity and 32 KiB boundary | REGRESSION_FIX / NEW_BEHAVIOR | old time-window case and missing size type fail | DONE |
| TST-102 / TSK-102 | REQ-102 | insert/issue/complete stage durations | NEW_BEHAVIOR | missing insert event/API | DONE |
| TST-103 / TSK-103 | REQ-105, INV-101/102 | union busy/idle/logging and grouped summary | NEW_BEHAVIOR | missing utilization/category APIs | DONE |
| TST-104 / TSK-104 | REQ-103, REQ-107 | file event schema/path confidence and v1 read | NEW_BEHAVIOR | missing wire variants | DONE |
| TST-105 / TSK-105 | REQ-104, REQ-106 | selectable chart projection and simulator coverage | NEW_BEHAVIOR | missing chart model/UI | DONE |
| TST-106 / TSK-106 | DoD | full build, docs, GitHub CI | CHARACTERIZATION | N/A; compile/regression evidence | DONE |

Working suite: `cargo test -p android-ebpf-protocol`

Commit suite: `cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace && cargo check -p android-ebpf-studio --features gui`
