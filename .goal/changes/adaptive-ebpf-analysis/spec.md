---
change_id: adaptive-ebpf-analysis
revision: 1
level: L3
execution_mode: DURABLE
route: DESIGN_FIRST
confirmation: CONFIRMED-AUTO
lifecycle: CONFIRMED
confirmed_by: current user plan request on 2026-08-27
baseline: 50c22c2 plus preserved pre-existing working-tree changes
---

# Adaptive eBPF Analysis Specification

## Goal

Android eBPF Storage Studio가 모든 원본 이벤트를 Windows로 전송한 뒤 매 화면 갱신마다 다시 분석하는 구조에서 벗어나, 커널과 agent에서 실시간 필터링·집계·tail 선별·이상 감지를 수행하고 Windows UI는 bounded snapshot과 선택된 상세 transaction을 증분 처리하도록 한다.

이번 문서는 구현 계획의 기준선이며 production code는 변경하지 않는다. 실제 구현을 시작할 때 현재 working tree와 이 기준선을 먼저 재조정한다.

## Current behavior

- [Repo evidence] eBPF collector는 block, syscall, optional FS/SCSI/UFS 이벤트를 대부분 ring buffer로 전송한다.
- [Repo evidence] `AnalysisEngine::summary`, `transaction_for`, `why_slow`, Explorer projection은 원본 sample과 graph를 반복 순회하거나 정렬한다.
- [Repo evidence] Protocol v4 graph와 file attribution, File Group By, 진단 record는 이미 존재한다.
- [User] Pipeline, Explorer뿐 아니라 전체 UI가 큰 session에서 버벅이며, eBPF 특유의 실시간 분석 기능 1~8 전체에 대한 구현 계획을 요청했다.

## Governing principles

- `AGGREGATE_FIRST`: 기본 모드에서는 exact count/bytes와 bounded histogram을 우선 전송한다.
- `DETAIL_BY_POLICY`: 상세 transaction은 tail, trigger, deterministic sample 또는 명시적 Raw-All 모드에서만 전송한다.
- `NO_FALSE_EXACTNESS`: histogram percentile은 approximate로, context는 additive latency가 아닌 `ContextOnly`로 표시한다.
- `BOUNDED_STATE`: 모든 BPF map, agent buffer, UI cache, top-N cardinality와 TTL은 설정 가능한 상한을 갖는다.
- `CONTROL_IS_AUDITABLE`: filter, mode, trigger와 sampling 변경은 generation과 reason을 session에 기록한다.
- `READ_ONLY_DEFAULT`: 분석 기능은 I/O 허용·차단·우선순위를 변경하지 않는다.
- `BACKWARD_READABLE`: 새 reader는 protocol v1~v4 session을 계속 읽는다.

## Functional requirements

### REQ-201 — Dynamic Filter Map

- GUI는 capture 중 PID/TID, UID, resolved package, device, operation, size range, latency threshold, inode/file identity를 변경할 수 있어야 한다.
- package와 path는 kernel 문자열 비교를 하지 않는다. Agent가 package를 UID/PID set으로, path를 가능한 경우 `(dev, inode, mount)`로 해석해 bounded key set을 map에 기록한다.
- filter update는 immutable config payload를 먼저 기록한 뒤 generation을 전환하여 event가 부분 설정을 보지 않게 한다.
- 적용·거부·축약된 filter와 generation을 control record 및 diagnostic log에 남긴다.

### REQ-202 — Kernel histogram and health

- eBPF는 per-CPU fixed bucket으로 total/queue/device 및 지원되는 FS/SCSI/UFS latency, size, queue depth 분포를 집계한다.
- count, bytes, failures는 exact counter로 유지하고 percentile은 histogram에서 도출된 approximate 값임을 표시한다.
- ring reserve failure, map insert failure, in-flight expiry/reuse, filter pass/drop, detail emitted/suppressed를 실제 counter로 제공한다.
- Agent는 기본 1초 간격으로 snapshot을 병합하며 snapshot 간 중복/누락을 막는 epoch 계약을 사용한다.

### REQ-203 — Slow-I/O detail selection

- 기본 `Balanced` 모드는 모든 요청을 aggregate에 포함하고 threshold를 넘는 transaction과 deterministic sample만 상세 전송한다.
- 정책은 total/queue/device/stage latency, status, correlation failure, operation, size를 조합할 수 있다.
- `RawAll`은 opt-in이며 UI에 높은 overhead 경고를 표시한다.
- fast I/O suppression 때문에 count/bytes/distribution이 사라지지 않아야 한다.

### REQ-204 — Live Top Offenders

- Process/UID, file identity/path snapshot, device, operation, stage, origin별 Top N을 count, bytes, cumulative latency, p99 bucket, maximum latency로 제공한다.
- PID/device/stage는 가능한 경우 kernel aggregate를 사용한다. File Top N은 exact file identity가 lower stack에 없을 수 있으므로 agent correlation 결과에서 계산하고 confidence 비율을 함께 표시한다.
- high-cardinality key는 bounded candidate table과 eviction count를 사용하며 Top N을 전체 모집단의 exact ranking으로 가장하지 않는다.

### REQ-205 — Adaptive capture state machine

- Agent는 `Basic -> Armed -> Deep -> Cooldown -> Basic` 상태를 관리한다.
- Trigger는 연속 snapshot 기준 p99 bucket, queue depth, UFS latency, error/drop rate 및 file/process 조건을 조합한다.
- Deep probe 활성화는 agent가 수행한다. eBPF 프로그램이 다른 프로그램을 attach하지 않는다.
- 모든 전이는 trigger evidence, config generation, 시작/종료 timestamp와 함께 session에 기록된다.

### REQ-206 — Triggered flight recorder

- Agent는 aggregate snapshot, sampled/tail transaction, control/health record를 시간 제한 순환 버퍼에 보관한다.
- Trigger 시 pre-window, deep-window, post-window를 하나의 segment로 확정한다.
- BPF ring buffer를 과거 저장소로 사용하지 않는다. Pre-trigger 보존은 bounded agent memory가 담당한다.
- 메모리 한도 초과 시 오래된 record를 폐기하고 손실량과 기간을 기록한다.

### REQ-207 — Slow-I/O context enrichment

- Deep 모드에서 선택 UID/PID/TID와 관련된 scheduler off-CPU, reclaim/writeback, F2FS GC/checkpoint, ext4 journal/writeback, UFS Hibern8/gear/reset/error context를 수집한다.
- 직접 key가 없으면 transaction edge를 만들지 않고 time-overlap `ContextOnly` marker로 보존한다.
- scheduler trace는 target task set과 bounded window로 제한한다.

### REQ-208 — Selective stack fingerprint

- Stack capture는 Deep 모드의 선택 대상과 sampling budget 안에서만 활성화한다.
- user stack은 syscall/file origin 시점, kernel stack은 relevant VFS/FS/block 시점의 stack ID로 구분한다.
- stack ID와 symbolization 상태를 분리하고, symbol/BPF stack support가 없으면 `Unavailable`로 표시한다.
- 동일 stack fingerprint별 count, tail 비율과 latency delta를 제공하되 앱 stack과 kworker stack을 혼동하지 않는다.

## Performance and quality requirements

- `NFR-201`: session parsing, graph build, percentile/top-N 계산과 export I/O는 GUI render thread에서 수행하지 않는다.
- `NFR-202`: analyzer는 ingest 시 summary, histogram, transaction graph와 grouping index를 증분 갱신한다. 동일 generation에서 UI query는 원본 전체를 재순회하지 않는다.
- `NFR-203`: detailed transaction, chart point, context marker, stack entry와 flight-recorder bytes는 각각 독립 상한과 eviction counter를 갖는다.
- `NFR-204`: reference Windows host와 deterministic simulator workload를 기록하고, 1M source-event session에서 p95 frame time 33 ms 이하, selector response 100 ms 이하를 release target으로 삼는다. 충족 여부는 실제 측정값으로만 판정한다.
- `NFR-205`: slow-request 비율이 5% 이하인 동일 workload에서 Balanced 상세 record 수가 RawAll 대비 90% 이상 감소해야 한다. Aggregate count/bytes는 동일해야 한다.
- `NFR-206`: target Android device에서 Off/Basic/Balanced/Deep별 CPU, map memory, output bytes/sec, reserve failure를 측정하기 전에는 overhead 목표를 통과했다고 표시하지 않는다.
- `NFR-207`: filter 적용은 정상 control channel에서 2 snapshot interval 이내 확인 가능해야 하며 generation mismatch는 진단 가능해야 한다.
- `NFR-208`: diagnostic log에는 full path, raw stack address, serial을 기본 기록하지 않는다. Session 분석 데이터와 explicit diagnostic-bundle opt-in은 기존 정책을 유지한다.

## Protocol v5 additions

- `CaptureConfigRecord`: mode, filter generation, bounded keys, detail and trigger policy.
- `AggregateSnapshotRecord`: interval/epoch, counters, histogram buckets, filter statistics.
- `HeavyHitterSnapshotRecord`: dimension, bounded candidates, metric and approximation metadata.
- `TriggerRecord`: rule evidence and capture-state transition.
- `SegmentRecord`: pre/deep/post time bounds and flight-recorder loss.
- `StackFingerprintRecord`: stack kind, opaque stack ID, frames/symbolization availability and cohort statistics.

Unknown v5 records remain reject-counted under the existing integrity contract; v1~v4 records import with aggregate/trigger/stack fields unavailable.

## Acceptance scenarios

- `SCN-201`: Capture 중 Read-only, UID 10001 filter를 적용하면 generation G+1 이후 다른 UID의 detail은 억제되고 모든 filter counters와 변경 record가 보인다.
- `SCN-202`: 100개 요청 중 3개가 threshold를 넘으면 aggregate count는 100이고 detail은 3개 plus configured deterministic samples다.
- `SCN-203`: p99 trigger가 3개 연속 snapshot에서 위반되면 Armed에서 Deep으로 전환하고, configured duration 이후 Cooldown을 거쳐 Basic으로 복귀한다.
- `SCN-204`: pre-window buffer가 한도를 초과하면 segment는 보존된 실제 범위와 eviction count를 표시한다.
- `SCN-205`: F2FS GC가 느린 request와 겹치지만 direct key가 없으면 Why Slow은 `concurrent context`로만 설명한다.
- `SCN-206`: stack 지원이 없는 커널에서도 capture는 계속되고 Stack UI는 0 samples가 아니라 Unavailable을 표시한다.
- `SCN-207`: 1M-event fixture를 열어 Explorer Group By를 변경해도 raw graph 재구성이 발생하지 않으며 NFR-204 benchmark 결과가 저장된다.

## Non-goals

- cgroup/LSM를 통한 I/O 차단, throttling 또는 priority 변경.
- path string을 eBPF hot path에서 조립하거나 비교하는 기능.
- approximate histogram에서 exact percentile을 복원했다고 주장하는 기능.
- vendor firmware/NAND 내부 시간을 tracepoint 없이 세분화하는 기능.
- user-build 보안 정책 우회와 symbol 자동 수집.

## Rollout and rollback

- `v0.6 Fast Live Foundation`: REQ-201~204, protocol v5, incremental UI query/index and performance benchmark.
- `v0.7 Adaptive Capture`: REQ-205~206 and trigger/segment UI.
- `v0.8 Deep RCA`: REQ-207~208 and confidence-aware live Why Slow.
- 각 기능은 capability와 feature flag로 분리한다. 문제 발생 시 `Legacy/RawAll` reader 경로가 아니라 `Basic aggregate + v4 detail compatibility`로 rollback한다.

## Definition of done

- 모든 Must requirement에 behavior test와 exact evidence가 연결된다.
- Rust format, Clippy `-D warnings`, workspace tests, Windows GUI check, Android arm64 agent build와 eBPF build가 통과한다.
- simulator 성능 fixture와 target Windows benchmark가 NFR-204/205를 증명한다.
- target Android Phone에서 capability, verifier/attach, Off/Basic/Balanced/Deep overhead와 drop을 측정한다.
- device에서 미검증한 계층이나 stack 기능은 release note에서 명시적으로 구분한다.
