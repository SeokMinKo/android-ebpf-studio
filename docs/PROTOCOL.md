# NDJSON Protocol v4

각 stdout line은 독립적인 JSON object이고 `record` discriminator와 `schema_version`을 가집니다.

## Record order

1. `hello`
2. `capabilities`
3. zero or more `event` / periodic `health`
4. graceful stop 시 `footer`

Reader는 알 수 없는 JSON field를 무시하지만, 알 수 없는 `record` type과 malformed/1 MiB 초과 line을 rejection으로 계산합니다.

## Examples

```json
{"record":"hello","schema_version":4,"agent_version":"0.5.0","boot_id":"...","kernel_release":"6.6.30-android15"}
{"record":"event","schema_version":4,"sequence":1,"event":{"kind":"block_issue","data":{"ts_ns":1000000,"request_id":4660,"device_major":259,"device_minor":0,"sector":1024,"sectors":8,"bytes":4096,"operation":"read","pid":4242,"tid":4242,"cpu":3,"comm":"fio"}}}
{"record":"event","schema_version":4,"sequence":2,"event":{"kind":"file_io","data":{"start_ts_ns":800000,"end_ts_ns":1300000,"operation":"read","fd":7,"requested_bytes":4096,"completed_bytes":4096,"pid":4242,"tid":4242,"comm":"fio","path":"/data/local/tmp/input.bin","confidence":"attributed","file_identity":{"fs_device_major":259,"fs_device_minor":7,"inode":1001,"mount_id":42},"path_snapshot":{"path":"/data/local/tmp/input.bin","source":"proc_fd","captured_ts_ns":1300000,"deleted":false}}}}
{"record":"event","schema_version":4,"sequence":3,"event":{"kind":"pipeline","data":{"ts_ns":1050000,"end_ts_ns":1210000,"phase":"span","layer":"ufs","correlation_id":null,"stage_key":17,"sector":1024,"bytes":4096,"opcode":40,"status":0,"pid":4242,"tid":4242,"name":"UFS command","confidence":"probable"}}}
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
- 하나의 block request는 여러 file-origin edge를 가질 수 있습니다. ambiguous 후보는 임의 선택하지 않습니다.
- `correlation_id`는 block transaction 직접 연결 키이고, `stage_key`는 SCSI/UFS tag처럼 계층 내부 pairing에만 정확한 키입니다. tracepoint가 제공하는 경우 `opcode`와 completion `status`도 paired observation과 waterfall span에 보존됩니다.
- agent는 kernel pointer와 command tag를 session salt로 pseudonymize한 뒤 내보냅니다. UFS controller identity가 없는 tag-only span은 재사용 검사를 통과해도 `probable`을 넘지 않습니다.

## Confidence

- `exact`: 직접 전파된 안정 ID/tag와 유효 lifetime 근거.
- `probable`: LBA/bytes/op/time/thread의 유일 후보.
- `probable_async`: inode/writeback 근거는 있으나 최초 syscall causation token이 없음.
- `context_only`: UIC/link/GC 같은 동시 컨텍스트이며 latency 합산 제외.

v1~v3 `hello`, `event`, `health`, `footer`는 계속 읽을 수 있습니다. 누락된 v4 필드는 unavailable로 해석합니다.

## Diagnostic stream

stderr의 각 줄은 별도 `DiagnosticRecord` JSON입니다. 최소 필드는 `schema_version`, `ts_unix_ms`, `level`, `component`, `event`, `session_id`, `outcome`, `code`이며 correlation/node/probe/duration/count는 선택적입니다. stdout measurement와 섞지 않습니다. full path와 payload는 diagnostic 기본 출력에서 redaction됩니다.

## Integrity

Session close invariant:

```text
events_seen = events_persisted + events_dropped + events_rejected
```

비정상 종료로 footer가 없으면 session은 partial로 취급해야 합니다.
