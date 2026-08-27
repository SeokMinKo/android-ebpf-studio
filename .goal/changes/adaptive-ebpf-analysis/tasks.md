# Task DAG — Adaptive eBPF Analysis

- Artifact: `tasks@1`
- Status: `CONFIRMED`
- Derived from: `spec@1`, `design@1`
- Execution: one implementation stream by default. Complete tasks in dependency order.

| Task | Scope | Depends | Primary proof |
|---|---|---|---|
| TSK-201 | Characterize v0.5 CPU/memory/frame/query/output baseline and add 1M-event fixture | — | Repeatable benchmark report |
| TSK-202 | Protocol v5 control/aggregate/heavy-hitter/trigger/segment/stack types and v1~v4 compatibility | 201 | Round-trip and compatibility tests |
| TSK-203 | Piped control channel, atomic filter config generation and BPF lookup maps | 202 | Live update/invalid config/concurrency tests |
| TSK-204 | Per-CPU histograms, exact counters, reserve/map/filter health and epoch snapshots | 202,203 | Bucket boundary, per-CPU merge, delta tests |
| TSK-205 | Incremental analyzer indexes, graph cache, background parsing/downsampling and render budgets | 201,202,204 | 1M-event UI benchmark gate |
| TSK-206 | Balanced slow-I/O/detail policy and composite tail transaction emission | 203,204 | 100 aggregate vs 3 tail scenario |
| TSK-207 | Live Top Offenders for process/file/device/stage with approximation metadata | 204,205,206 | Eviction/tie/confidence/top-N tests |
| TSK-208 | Adaptive Basic/Armed/Deep/Cooldown controller and probe gating | 203,204,206 | Deterministic virtual-clock state tests |
| TSK-209 | Bounded pre/deep/post flight recorder and segment persistence | 208 | Window/capacity/priority eviction tests |
| TSK-210 | Scheduler/writeback/GC/UFS context adapters and ContextOnly overlay | 208,209 | Direct-vs-context attribution tests |
| TSK-211 | Deep-only user/kernel stack fingerprints and background symbolization | 208,209 | Unsupported/sampling/namespace tests |
| TSK-212 | Live Why Slow integration, diagnostics, docs, target-device validation and releases | 207,210,211 | Full CI, benchmark, device evidence |

## Per-task execution contract

### TSK-201 — Baseline and harness

- Paths: `crates/protocol/benches/**`, `crates/desktop/tests/**`, `.goal/changes/adaptive-ebpf-analysis/evidence/**`.
- First check: current implementation has no reproducible frame/query/output benchmark.
- Output: deterministic generators for low/high queue depth, file cardinality and complete pipeline events; reference host metadata and v0.5 baseline.
- DoD: baseline records raw event count, NDJSON bytes, load time, peak memory, summary/query time and p50/p95/max frame time without claiming device overhead.

### TSK-202 — Protocol v5

- Paths: `crates/protocol/**`, `crates/ebpf-types/**`, `docs/PROTOCOL.md`.
- First RED: v5 records and compatibility readers do not exist.
- Observability: every record carries session/config generation and bounded cardinality metadata.
- DoD: malformed boundary/replay/out-of-order/unknown-record behavior and v1~v4 import are tested.

### TSK-203 — Dynamic filter control

- Paths: `crates/desktop/src/capture.rs`, `crates/desktop/src/adb.rs`, `crates/android-agent/**`, `crates/android-ebpf/**`, `crates/ebpf-types/**`.
- First RED: capture child cannot accept a versioned filter command and collector has no filter map.
- Observability: `FILTER_UPDATE_REQUESTED/APPLIED/REJECTED`, generation, bounded key counts and redacted reason.
- DoD: atomic activation, last-known-good retention, rapid update race, empty/missing/oversized key set and disconnected stdin tests pass.

### TSK-204 — Histogram and health

- Paths: `crates/android-ebpf/**`, `crates/android-agent/**`, `crates/protocol/**`.
- First RED: all events are streamed and kernel drops remain unavailable.
- Observability: map read failures and every suppression/drop path has a counter.
- DoD: exact count/bytes, approximate bucket semantics and snapshot delta/restart behavior are tested.

### TSK-205 — Fast analyzer/UI foundation

- Paths: `crates/protocol/**`, `crates/desktop/src/app.rs`, `crates/desktop/src/session.rs`, focused tests/benchmarks.
- First RED: summary/Explorer/Pipeline repeatedly rebuild graphs or sort raw vectors and miss NFR-204.
- Observability: debug-only query timing, cache hit/miss, retained/evicted chart points and UI channel backlog.
- DoD: no disk I/O/full sort/full graph reconstruction on render path; 1M-event benchmark reaches the documented release target on the named host.

### TSK-206 — Tail detail policy

- Paths: eBPF/agent/protocol/desktop capture settings and tests.
- First RED: fast and slow requests are emitted identically.
- Observability: `detail_emitted`, `suppressed_fast`, `sampled`, `forced_error`, threshold rule.
- DoD: aggregates remain identical across Basic/Balanced/RawAll and deterministic sampling is reproducible from session salt.

### TSK-207 — Top Offenders

- Paths: protocol analyzer/index, agent aggregation, desktop Live/Summary UI.
- First RED: no bounded live ranking or approximation metadata exists.
- Observability: candidate capacity, evictions and metric coverage ratio.
- DoD: file Group By uses stable file identity, multi-origin does not collapse to one path, and changing ranking metric does not rescan raw events on UI thread.

### TSK-208 — Adaptive controller

- Paths: agent controller, protocol policies, desktop Triggers UI.
- First RED: no capture state or automatic transition exists.
- Observability: every transition records old/new state, rule evidence, duration/size budget and reason.
- DoD: hysteresis, consecutive windows, cooldown, retrigger budget, manual override and unsupported deep probe cases pass with a virtual clock.

### TSK-209 — Flight recorder

- Paths: agent buffer/segment writer, protocol segment records, desktop session navigation.
- First RED: trigger cannot preserve pre-window data.
- Observability: retained actual window, bytes, per-priority evictions, freeze/write failures.
- DoD: memory remains bounded under sustained events and a partial/crashed segment remains readable with integrity status.

### TSK-210 — Context enrichment

- Paths: ebpf-types/collector adapters, agent capability/attach plans, protocol graph, desktop overlay.
- First RED: slow request has no bounded scheduler/writeback/GC/UFS context lanes.
- Observability: per-probe emitted/suppressed/pair/expiry counters.
- DoD: unsupported vendor layouts are isolated; context without direct key never becomes additive or Exact.

### TSK-211 — Stack fingerprints

- Paths: eBPF stack map/programs, agent symbol adapter, protocol cohort index, desktop RCA UI.
- First RED: no distinct user/kernel stack identity or unavailable semantics.
- Observability: attempts/success/map-full/unwind-failure/symbol-hit counters without raw addresses in diagnostic logs.
- DoD: Deep/filter/sampling budgets gate stack capture and user/kworker namespaces remain separate.

### TSK-212 — Conformance and release

- Paths: all affected docs/tests/workflows plus this change's evidence artifacts.
- DoD: v0.6, v0.7, v0.8 gates are independently releasable; no release claims target-device overhead or vendor probe support without exact device evidence.

## Release waves

### v0.6 — Fast Live Foundation

- TSK-201~207.
- User-visible: Live filters, aggregate dashboard, smooth Summary/Pipeline/Explorer, slow-I/O-only detail, Top Offenders.
- Gate: Windows performance benchmark and protocol compatibility are mandatory; Android overhead evidence is reported separately.

### v0.7 — Adaptive Capture

- TSK-208~209.
- User-visible: Trigger rules, state timeline, pre/deep/post segments and automatic Deep Capture.
- Gate: state-machine and memory-bound stress tests plus one target-device capture.

### v0.8 — Deep RCA

- TSK-210~212.
- User-visible: scheduler/writeback/GC/UFS context, stack fingerprints and live Why Slow.
- Gate: capability fallbacks, redaction, context accuracy and target-device proof for every advertised measured layer.
