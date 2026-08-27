# Design — Adaptive eBPF Analysis

- Artifact: `design@1`
- Status: `CONFIRMED`
- Derived from: `spec@1`

## Architecture

분석 경로를 세 plane으로 분리한다.

1. **Control plane**: Windows GUI가 agent에 versioned config command를 보내고 agent가 BPF config map과 capture state를 갱신한다.
2. **Aggregate plane**: eBPF per-CPU counters/histograms → agent epoch merge → protocol snapshot → incremental UI index.
3. **Detail plane**: tail/sample/trigger 대상의 bounded transaction, context와 stack만 ring buffer → agent flight recorder → session/UI.

기존 measurement stdout과 diagnostic stderr 분리는 유지한다. 실시간 command는 adb capture process의 piped stdin에 length-bounded JSONL을 전달하고, agent는 stdout에 `CaptureConfigRecord` acknowledgement를 기록한다. stdin 전달이 특정 adb 환경에서 불가능하면 session-scoped Unix socket control adapter를 대체 경로로 사용하되 두 경로는 동일 command contract를 구현한다.

## Kernel data model

- `FILTER_CONFIG_A/B`: 두 config slot과 active generation. 완성된 inactive slot을 기록한 뒤 active generation을 전환한다.
- `FILTER_PID_UID`, `FILTER_FILE`: bounded lookup sets. Empty set semantics는 명시적 `match_all` bit로 구분한다.
- `IN_FLIGHT`: request/stage start와 compact correlation state. Key reuse와 TTL을 검증한다.
- `HISTOGRAMS`: per-CPU fixed bucket arrays. Stage/operation/device의 bounded dimension만 kernel에 둔다.
- `HEALTH_COUNTERS`: per-CPU reserve/map/filter/detail counters.
- `STACK_TRACES`: Deep-only bounded stack trace map.

Kernel path에서 문자열, dynamic allocation, unbounded loop 또는 top-N sorting을 하지 않는다.

## Histogram contract

- Duration은 ns 단위 log2 또는 explicit fixed boundaries로 bucket한다. Boundary list는 protocol에 함께 기록한다.
- Count/bytes는 exact, percentile은 해당 rank가 포함된 bucket 범위로 표현한다.
- Epoch snapshot은 `(boot_id, session_id, epoch, config_generation, start_ns, end_ns)`로 식별한다.
- Map clear race를 피하기 위해 double-buffered epoch 또는 monotonic cumulative snapshot-delta 중 실제 aya/kernel 지원으로 더 단순하고 검증 가능한 방식을 선택한다. 기본안은 cumulative per-CPU counter를 agent가 읽고 이전 값을 빼는 방식이다.

## Analyzer and UI performance

- `AnalysisEngine` ingest가 immutable `AnalysisSnapshot` generation을 만든다.
- request별 `IoTransactionGraph`, stage durations, file/origin/confidence key를 completion 시 한 번 계산해 cache한다.
- percentile은 raw `Vec` sort가 아니라 histogram/online aggregate를 사용한다. RawAll session의 exact percentile 요청은 background job으로만 계산한다.
- Explorer는 selected axes/filter/group key로 materialized projection을 cache하고 generation 변경분만 append한다.
- plot point가 pixel budget을 넘으면 deterministic min/max/LTTB 계열 downsampling을 background에서 수행한다. 선택된 tail point는 절대 제거하지 않는다.
- UI thread는 channel drain budget, snapshot pointer swap과 bounded rendering만 수행한다.

## Detail selection

- `Basic`: counters/histograms/health only, optional low-rate deterministic sample.
- `Balanced`: aggregate all + tail/error/correlation-failure + sample detail.
- `Deep`: selected filter scope의 pipeline/context/stack detail.
- `RawAll`: compatibility/debug mode; explicit warning and duration guard.

Threshold 판정에 필요한 start/stage state는 BPF map에 보존하고 completion에서 composite detail record를 생성한다. 서로 다른 계층의 exact correlation이 불가능하면 agent가 기존 v4 graph evidence를 사용하되 confidence를 높이지 않는다.

## Heavy hitters

- Kernel: bounded stable dimensions(PID/UID/device/op/stage)의 counters.
- Agent: file identity/origin/confidence를 포함한 candidate table과 min-heap Top N.
- Snapshot은 `candidate_capacity`, `evicted_keys`, `covered_metric/total_metric`을 포함해 정확도 한계를 보여준다.

## Adaptive controller

- State transitions:
  - Basic → Armed: rule 조건 1회 관측.
  - Armed → Deep: configured consecutive windows 충족.
  - Armed → Basic: 조건 해제 또는 arming timeout.
  - Deep → Cooldown: capture duration/size budget 도달.
  - Cooldown → Deep: severe retrigger와 retrigger budget 허용.
  - Cooldown → Basic: cooldown 종료.
- Controller는 agent 단일 소유이며 GUI는 정책을 설정할 뿐 상태를 직접 강제하지 않는다. Manual Deep은 별도의 user reason을 가진 transition command다.

## Flight recorder

- Agent ring은 serialized size로 제한된 `VecDeque<Arc<Record>>` 형태를 사용한다.
- Aggregate/health/control은 항상 보존 우선순위가 높고, sampled detail → context → stack 순으로 먼저 evict한다.
- Trigger 후 segment writer가 pre-window reference를 freeze하고 deep/post record를 append한다. 동일 record를 메모리에서 복제하지 않는다.

## Context and stack correctness

- Context overlay는 time range와 filter scope가 겹치는 사실만 표현한다.
- Off-CPU span은 sched_switch out/in pair가 유효할 때만 measured span이다.
- User stack은 syscall origin, kernel stack은 probe site 의미를 갖는다. 두 fingerprint namespace를 분리한다.
- Address symbolization은 agent/desktop background 단계이고 원본 address는 diagnostic log에 기록하지 않는다.

## Failure isolation

- Invalid command/config: 이전 generation 유지, NACK와 reason 기록.
- Aggregate map read failure: detail capture 계속, snapshot unavailable 표시.
- Detail ring pressure: aggregate 계속, reserve failure counter 증가.
- Deep probe attach failure: 가능한 계층만 Deep, 실패 계층 Unavailable.
- Stack collection/symbol failure: transaction/context는 유지, stack만 Unavailable.
- Flight recorder capacity exhaustion: capture 지속, actual retained window와 eviction 표시.
