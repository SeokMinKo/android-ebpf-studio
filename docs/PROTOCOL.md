# NDJSON Protocol v5

각 stdout line은 독립적인 JSON object이고 `record` discriminator와 `schema_version`을 가집니다.

## Record order

1. `hello`
2. `capabilities`
3. zero or more `event` / periodic `aggregate` / `heavy_hitters` / `health`
4. optional `control` / `trigger` / `segment` / `stack_fingerprint`
5. graceful stop 시 `footer`

Reader는 알 수 없는 JSON field를 무시하지만, 알 수 없는 `record` type과 malformed/1 MiB 초과 line을 rejection으로 계산합니다.

## Examples

```json
{"record":"hello","schema_version":5,"agent_version":"0.8.0","boot_id":"...","kernel_release":"6.6.30-android15"}
{"record":"event","schema_version":5,"sequence":1,"event":{"kind":"block_issue","data":{"ts_ns":1000000,"request_id":4660,"device_major":259,"device_minor":0,"sector":1024,"sectors":8,"bytes":4096,"operation":"read","pid":4242,"tid":4242,"cpu":3,"comm":"fio"}}}
{"record":"aggregate","schema_version":5,"snapshot":{"session_id":"...","epoch":1,"config_generation":2,"start_ts_ns":0,"end_ts_ns":1000000000,"counters":{"observed":1000,"bytes":4096000,"failed":0,"filter_passed":1000,"filter_suppressed":0,"detail_emitted":47,"suppressed_fast":953,"sampled":10,"forced_error":0,"ring_reserve_failures":0,"map_insert_failures":0,"expired":0,"key_reused":0},"histograms":[]}}
```

## Time and units

- `ts_ns`: device monotonic clock in nanoseconds; wall-clock이 아닙니다.
- `sector`: 512-byte logical sector unit from block tracepoint.
- `bytes`: request payload bytes.
- queue latency: insert→issue, device latency: issue→complete, total latency: insert(없으면 issue)→complete.
- logging time은 첫 관측 timestamp부터 마지막 관측 timestamp까지입니다.
- busy time은 완료된 block request interval의 합집합이며 중첩 요청을 중복 합산하지 않습니다.
- Pipeline measured coverage도 additive span의 합집합입니다. `context_only` UIC marker는 표시되지만 latency 합산에서 제외됩니다.

## File identity와 transaction graph

- `FileIdentity`는 filesystem device/inode와 선택적 generation/mount ID로 구성되며 경로와 분리됩니다.
- `PathSnapshot`은 관측 시점의 이름이므로 rename/unlink 뒤에도 identity를 대체하지 않습니다.
- `node`와 `edge` event는 `transaction_id`로 소속 request를 명시합니다. 이름 문자열이나 raw pointer를 export correlation key로 사용하지 않습니다.
- `request_origin` event는 typed kernel hook이 직접 전달한 `request_id`, opaque `origin_id`, `FileIdentity`, origin 분류와 bounded-set `incomplete` 상태를 담습니다. 분석기는 이를 request로 향하는 `exact` edge로 materialize합니다.
- 하나의 block request는 여러 file-origin edge를 가질 수 있습니다. ambiguous 후보는 임의 선택하지 않습니다.
- exact origin이 하나라도 있으면 같은 request의 시간/task/size 기반 file 후보는 추가하지 않습니다. 동일 identity의 `FileIo`는 edge 후보가 아니라 path snapshot 보강에만 사용됩니다.
- `correlation_id`는 block transaction 직접 연결 키이고, `stage_key`는 SCSI/UFS tag처럼 계층 내부 pairing에만 정확한 키입니다. tracepoint가 제공하는 경우 `opcode`와 completion `status`도 paired observation과 waterfall span에 보존됩니다.
- agent는 kernel pointer와 command tag를 session salt로 pseudonymize한 뒤 내보냅니다. UFS controller identity가 없는 tag-only span은 재사용 검사를 통과해도 `probable`을 넘지 않습니다.

## Confidence

- `exact`: 직접 전파된 안정 ID/tag와 유효 lifetime 근거.
- `probable`: LBA/bytes/op/time/thread의 유일 후보.
- `probable_async`: inode/writeback 근거는 있으나 최초 syscall causation token이 없음.
- `context_only`: UIC/link/GC 같은 동시 컨텍스트이며 latency 합산 제외.

## v5 adaptive records

- `control`: requested/active generation과 applied/rejected 결과.
- `aggregate`: eBPF per-CPU counter/histogram의 epoch snapshot. detail suppression과 무관하게 전체 filtered I/O를 집계합니다.
- `heavy_hitters`: bounded candidate Top-N, capacity/eviction/coverage를 함께 제공합니다.
- `trigger`: Basic/Armed/Deep/Cooldown 전환과 rule evidence.
- `segment`: 요청/실제 pre-window, 종료, retained bytes와 eviction 수.
- `stack_fingerprint`: session-salted opaque stack ID, user/kernel namespace, frame/sample/tail 집계. raw address는 diagnostic에 기록하지 않습니다.

v1~v4 `hello`, `event`, `health`, `footer`는 계속 읽을 수 있습니다. 누락된 v5 필드는 unavailable로 해석합니다.

## Diagnostic stream

stderr의 각 줄은 별도 `DiagnosticRecord` JSON입니다. 최소 필드는 `schema_version`, `ts_unix_ms`, `level`, `component`, `event`, `session_id`, `outcome`, `code`이며 correlation/node/probe/duration/count는 선택적입니다. stdout measurement와 섞지 않습니다. full path와 payload는 diagnostic 기본 출력에서 redaction됩니다.

## Integrity

Session close invariant:

```text
events_seen = events_persisted + events_dropped + events_rejected
```

비정상 종료로 footer가 없으면 session은 partial로 취급해야 합니다.
