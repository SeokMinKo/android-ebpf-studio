# Evidence ledger

| Sequence/time | Spec IDs | Task/Test ID | Exact command/check | Exit/status | Raw summary | Evidence scope | Revision |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 0001 / 2026-08-27 | all | P1 | `git status --short --branch && git log -5 --oneline` | 0 | clean v0.5.1 content baseline before branch | repository reconciliation | spec@1 |
| 0002 / 2026-08-27 | all | TSK-001..005 / TST-001..003 | GitHub Actions run `33038722552` | success | format, Clippy, workspace tests, Windows GUI check, Android arm64 agent, and eBPF object all succeeded | executable regression/compile proof at `8f60a733` | spec@1 |
