# Evidence ledger — deep-io-attribution-pipeline

GitHub CI 기반 compile/test evidence를 확보했다. 실제 Android 단말 behavior 검증은 별도 gap으로 남아 있다.

| Sequence/time | Spec IDs | Task/Test ID | Exact command/check | Exit/status | Raw summary | Evidence scope | Artifact revision |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 0001 | REQ-001~069, NFR-001~009 | SPEC-CHECK | `git status --short && git log -5 --oneline --decorate` | 0 | baseline `10b2d8f`; pre-existing tree clean before Spec files | repository baseline inspection | spec@1 |
| 0002 / 2026-08-26T21:25Z | all | STATIC-001 | `git diff --check` | 0 | no whitespace errors | patch whitespace integrity only; not Rust compilation | spec@1 |
| 0003 / 2026-08-26T21:25Z | all | STATE-001 | `python3 -m json.tool .../run-state.json` and SHA-256 comparison | 0 | valid JSON; spec hash matches `e56e3317...c5d7` | durable state syntax and governing Spec identity | spec@1 |
| 0004 / 2026-08-26T21:25Z | NFR-008 | VERSION-001 | Python manifest/workflow consistency check | 0 | workspace=0.5.0 ebpf=0.5.0 release=v0.5.0 | declared package/release version consistency | spec@1 |
| 0005 / 2026-08-26T21:25Z | all Rust requirements | RUST-SUITE | `cargo fmt --check`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo test --workspace`; `cargo check -p android-ebpf-studio --features gui` | ENV / 127 each | `/bin/bash: cargo: command not found` | NOT RUN; provides no compile/test evidence | spec@1 |
| 0006 / 2026-08-26T21:25Z | REQ-001~036, NFR-001/009 | DEVICE-SUITE | target Android preflight/capture | BLOCKED | no Android Phone attached to this environment | verifier, SELinux, tracepoint compatibility and overhead remain unverified | spec@1 |
| 0007 / 2026-08-26T23:14Z | REQ-001~069, NFR-001~008 | CI-33022453624 | `cargo fmt --check`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo test --workspace`; Windows GUI check; Android arm64 agent build; eBPF object build | SUCCESS | all four jobs and every gated step passed at `aad7d92c` | compile, lint, unit/integration tests and cross-target build evidence; excludes target-device runtime and rendered UI review | spec@1 |
