# Tasks and Behavior Test List

## Task graph

- TSK-001 (REQ-001, REQ-002): protocol model and overlap-safe pipeline analysis.
- TSK-002 (REQ-003, REQ-006; depends TSK-001): correlator integration and simulator.
- TSK-003 (REQ-004; depends TSK-001): capability inventory and optional collector adapters.
- TSK-004 (REQ-005; depends TSK-002): interactive Pipeline UI.
- TSK-005 (all; depends TSK-003, TSK-004): docs, convergence and verification.
- TSK-006 (REQ-007; independent implementation folded into desktop stream): automatic artifact and session paths.

## Test strategy

### DEC-TST-001: inside-out
- Dominant risk: latency accounting and confidence semantics.
- First proof boundary: public protocol analysis API.
- Acceptance confirmation: simulator-fed desktop build and protocol integration tests.

| TST ID | Spec IDs | Behavior | Kind | Boundary | Expected RED | Status |
| --- | --- | --- | --- | --- | --- | --- |
| TST-001 | REQ-001, REQ-002, CON-001/2 | overlapping additive spans produce bounded union and Unaccounted | NEW_BEHAVIOR | protocol unit | missing pipeline public types/API | LISTED |
| TST-002 | REQ-002, NFR-002 | context-only UIC does not change accounting | NEW_BEHAVIOR | protocol unit | context marker incorrectly/missing from model | LISTED |
| TST-003 | REQ-003 | exact correlation outranks probable overlap | NEW_BEHAVIOR | analysis component | missing pipeline correlator | LISTED |
| TST-004 | REQ-006, SCN-003 | simulator produces every layer | NEW_BEHAVIOR | desktop component | simulator has only block/file events | LISTED |
| TST-005 | REQ-004, SCN-004 | probe inventory distinguishes optional layer availability | NEW_BEHAVIOR | agent unit | missing classified capability fields | LISTED |
| TST-006 | REQ-005 | Pipeline page compiles and renders bounded data | NEW_BEHAVIOR | GUI compile/simulator | missing page and waterfall | LISTED |
| TST-007 | NFR-001 | schema-v2 session remains readable | CHARACTERIZATION | protocol contract | N/A; preserve current serde behavior | LISTED |
| TST-008 | REQ-007, SCN-005 | intact release bundle resolves all capture paths automatically | NEW_BEHAVIOR | desktop component | missing path resolver | LISTED |

- Working suite: `cargo test -p android-ebpf-protocol --test pipeline_stages`
- Commit suite: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace && cargo check -p android-ebpf-studio --features gui`
- Doubles: deterministic simulator is a Fake for device event production; semantic obligations are protocol-valid ordering and all layer types.
