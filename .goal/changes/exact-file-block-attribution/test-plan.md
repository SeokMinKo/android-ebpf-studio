# Test plan

| Test | Requirement | Evidence |
| --- | --- | --- |
| Exact origin materializes exact graph edge | REQ-005, INV-002 | protocol unit test |
| Two distinct origins survive one request | REQ-004, INV-003 | protocol unit test |
| Exact origin suppresses competing heuristic file edge | REQ-005 | protocol unit test |
| Old NDJSON without origin records still parses and correlates as probable | REQ-007 | serde/analysis regression test |
| Origin ABI decode hashes object keys and preserves identity | REQ-002, NFR-002 | agent unit test |
| Overflow/incomplete flag survives to graph/diagnostics | REQ-008, NFR-001 | protocol/agent unit test |
| Missing BTF or attach failure retains mandatory block capture | REQ-001, REQ-007, NFR-004 | capability/attach unit test |
| Workspace format, clippy, tests | all host-verifiable | exact command evidence |
| eBPF target compiles | REQ-002..004 | repository eBPF build script |
| Load/attach/verifier and real workloads | all device-dependent | target-phone evidence; blocked locally |

TDD order is one active behavior at a time: exact graph contract, ABI decode, attach fallback, then typed probe integration.
