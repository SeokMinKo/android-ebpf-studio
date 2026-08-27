# Test and Observability Plan — spec@1

## Dominant risks

- Hot-path overhead grows despite reducing output.
- Filter update is partially applied or loses the last-known-good config.
- Suppressed detail causes aggregate bias or false exact percentile claims.
- Adaptive controller oscillates or captures an unbounded amount of data.
- Context and stack evidence is presented as direct causality.
- UI moves expensive work off one page but still blocks the render thread elsewhere.

## Behavior test list

| Test | Spec | Level | Expected first RED |
|---|---|---|---|
| TST-201 | NFR-201~205 | benchmark/component | current raw re-sort/rebuild misses target |
| TST-202 | REQ-201 | unit/integration | no config/control/filter map contract |
| TST-203 | REQ-202 | eBPF host fixture/integration | no histogram/counter snapshot |
| TST-204 | REQ-203 | integration | fast and slow detail are identical |
| TST-205 | REQ-204 | unit/component | no bounded top-N index |
| TST-206 | REQ-205 | unit with virtual clock | no state machine/hysteresis |
| TST-207 | REQ-206 | component/stress | no pre-trigger retained segment |
| TST-208 | REQ-207 | fixture/integration | context absent or misclassified |
| TST-209 | REQ-208 | fixture/integration | no stack capability/fingerprint contract |
| TST-210 | all | Windows/Android E2E | packaged capture evidence unavailable until devices run |

## Required benchmark evidence

- Same fixture and host: v0.5 baseline vs v0.6 candidate.
- Source events, retained detail, aggregate snapshots and session bytes.
- Agent process CPU/RSS, GUI load time/RSS, p50/p95/max frame and selector response.
- Target phone: capture-off, Basic, Balanced, Deep CPU and output bytes/sec; BPF map memory and reserve failures where available.
- No inferred or simulator-only value may be labelled target-device overhead.

## Diagnostic contract

- Control: command/request/applied generation, rejected reason, state transition.
- Aggregate: epoch/duration/map-read outcome, counter delta and bucket boundary hash.
- Detail: emitted/suppressed/sample/forced reason and correlation confidence.
- Flight recorder: actual retained bounds, bytes and priority eviction counts.
- Stack/context: capability, attach, pair/unwind/symbol outcome and unavailable reason.
- UI: background job duration, snapshot generation, cache hit/miss, backlog and point eviction; TRACE only for per-query detail.

## Exact verification command set

Commands may be refined to repository-supported package names during TSK-201 but the release suite must include:

```text
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo check -p android-ebpf-studio --features gui
cargo test -p android-ebpf-protocol --test adaptive_analysis
cargo test -p android-ebpf-agent --test control_and_snapshots
```

Android arm64 agent and eBPF object builds remain mandatory in CI. Actual phone tests are a separate evidence row, not implied by compilation.
