# Tasks

| ID | Scope | Depends | TDD | Status |
| --- | --- | --- | --- | --- |
| TSK-001 | Protocol request-origin contract, exact precedence, multi-origin graph tests | - | yes | done |
| TSK-002 | Shared kernel event ABI and decode tests | TSK-001 | yes | done |
| TSK-003 | Typed BTF eBPF origin capture and bounded propagation | TSK-002 | no (target verifier gate) | done_host |
| TSK-004 | Agent capability/attach/fallback and graph event conversion | TSK-002, TSK-003 | characterization | done |
| TSK-005 | Documentation, format/clippy/test/build/static verification | TSK-004 | no | done |
| TSK-006 | Target Android verifier and workload acceptance | TSK-005 | no | blocked_device |
| TSK-007 | Cross-environment implementation and device-validation handoff | TSK-005 | no | done |

## Traceability

- TSK-001: REQ-004..007, INV-001..004
- TSK-002: REQ-002..005, REQ-008, NFR-002
- TSK-003: REQ-002..004, REQ-008, NFR-001..003, INV-005
- TSK-004: REQ-001, REQ-005..008, NFR-004
- TSK-005: all host-verifiable requirements
- TSK-006: verifier and device-dependent acceptance contract
- TSK-007: REQ-001, REQ-007, NFR-004 operational continuation and evidence integrity
