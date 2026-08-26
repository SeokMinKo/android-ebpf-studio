# Test & Observability Plan — spec@1

- Artifact: `test-plan@2`
- Status: `CONFIRMED`
- Derived from: `spec@1`, `design@1`, `tasks@2`. Revision 2 only reconciles execution status; test behaviors and proof boundaries are unchanged.
- Strategy: deliberate hybrid — inside-out graph core, then outside-in agent/desktop boundaries.
- Working suite: crate-specific `cargo test -p <crate> <test>`.
- Commit suite: `cargo fmt --check`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo test --workspace`; GUI check.
- Current environment blocker: `cargo` command unavailable; record all Rust commands as NOT RUN until a Rust toolchain exists.

| TST | Spec | Behavior | Kind | Boundary | Expected RED | Status |
| --- | --- | --- | --- | --- | --- | --- |
| TST-001 | REQ-010~014 | identity/path v4 round trip | NEW_BEHAVIOR | protocol | missing types | LISTED |
| TST-002 | REQ-020~027 | multi-origin DAG and ambiguity | NEW_BEHAVIOR | analysis core | missing graph builder | LISTED |
| TST-003 | REQ-040~042 | union/exclusive/critical path | NEW_BEHAVIOR | analysis core | missing calculations | LISTED |
| TST-004 | REQ-031~035 | lower-stack fixture decoding | NEW_BEHAVIOR | agent adapter | missing layouts/events | LISTED |
| TST-005 | REQ-060~069 | continuous structured diagnostics | NEW_BEHAVIOR | process boundary | stderr is one-shot text | LISTED |
| TST-006 | REQ-050~055 | multi-origin graph/RCA UI model | NEW_BEHAVIOR | desktop component | missing view model | LISTED |
| TST-007 | NFR-008 | legacy v1~v3 read | CHARACTERIZATION | session reader | N/A; preserve baseline | LISTED |
| TST-008 | NFR-009 | device overhead modes | NEW_BEHAVIOR | real Android | target device unavailable | BLOCKED |

All Rust-backed items remain `LISTED`, not Green: the current environment has no `cargo` executable. Code presence is not test evidence.

Diagnostics assertions cover stable event/code, correlation propagation, no raw path/serial, counter monotonicity, failure retention and bounded fields.
