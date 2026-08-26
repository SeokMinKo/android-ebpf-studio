# NDJSON Protocol v2

각 stdout line은 독립적인 JSON object이고 `record` discriminator와 `schema_version`을 가집니다.

## Record order

1. `hello`
2. `capabilities`
3. zero or more `event` / periodic `health`
4. graceful stop 시 `footer`

Reader는 알 수 없는 JSON field를 무시하지만, 알 수 없는 `record` type과 malformed/1 MiB 초과 line을 rejection으로 계산합니다.

## Examples

```json
{"record":"hello","schema_version":2,"agent_version":"0.1.0","boot_id":"...","kernel_release":"6.6.30-android15"}
{"record":"event","schema_version":2,"sequence":1,"event":{"kind":"block_insert","data":{"ts_ns":900000,"request_id":4660,"device_major":259,"device_minor":0,"sector":1024,"sectors":8,"bytes":4096,"operation":"read"}}}
{"record":"event","schema_version":2,"sequence":2,"event":{"kind":"block_issue","data":{"ts_ns":1000000,"request_id":4660,"device_major":259,"device_minor":0,"sector":1024,"sectors":8,"bytes":4096,"operation":"read","pid":4242,"tid":4242,"cpu":3,"comm":"fio"}}}
{"record":"event","schema_version":2,"sequence":3,"event":{"kind":"block_complete","data":{"ts_ns":1250000,"request_id":4660,"device_major":259,"device_minor":0,"status":0}}}
{"record":"event","schema_version":2,"sequence":4,"event":{"kind":"file_io","data":{"start_ts_ns":800000,"end_ts_ns":1300000,"operation":"read","fd":7,"requested_bytes":4096,"completed_bytes":4096,"pid":4242,"tid":4242,"comm":"fio","path":"/data/local/tmp/input.bin","confidence":"attributed"}}}
```

## Time and units

- `ts_ns`: device monotonic clock in nanoseconds; wall-clock이 아닙니다.
- `sector`: 512-byte logical sector unit from block tracepoint.
- `bytes`: request payload bytes.
- queue latency: insert→issue, device latency: issue→complete, total latency: insert(없으면 issue)→complete.
- logging time은 첫 관측 timestamp부터 마지막 관측 timestamp까지입니다.
- busy time은 완료된 block request interval의 합집합이며 중첩 요청을 중복 합산하지 않습니다.

v1 `hello`, `event`, `health`, `footer`는 계속 읽을 수 있습니다. v1 block event에는 insert/file 정보가 없으므로 해당 필드는 unavailable입니다.

## Integrity

Session close invariant:

```text
events_seen = events_persisted + events_dropped + events_rejected
```

비정상 종료로 footer가 없으면 session은 partial로 취급해야 합니다.
