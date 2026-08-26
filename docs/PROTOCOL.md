# NDJSON Protocol v1

각 stdout line은 독립적인 JSON object이고 `record` discriminator와 `schema_version`을 가집니다.

## Record order

1. `hello`
2. `capabilities`
3. zero or more `event` / periodic `health`
4. graceful stop 시 `footer`

Reader는 알 수 없는 JSON field를 무시하지만, 알 수 없는 `record` type과 malformed/1 MiB 초과 line을 rejection으로 계산합니다.

## Examples

```json
{"record":"hello","schema_version":1,"agent_version":"0.1.0","boot_id":"...","kernel_release":"6.6.30-android15"}
{"record":"event","schema_version":1,"sequence":1,"event":{"kind":"block_issue","data":{"ts_ns":1000000,"request_id":4660,"device_major":259,"device_minor":0,"sector":1024,"sectors":8,"bytes":4096,"operation":"read","pid":4242,"tid":4242,"cpu":3,"comm":"fio"}}}
{"record":"event","schema_version":1,"sequence":2,"event":{"kind":"block_complete","data":{"ts_ns":1250000,"request_id":4660,"device_major":259,"device_minor":0,"status":0}}}
{"record":"health","schema_version":1,"emitted_events":2,"kernel_drops":0,"userspace_drops":0}
{"record":"footer","schema_version":1,"events_seen":2,"events_persisted":2,"events_dropped":0,"events_rejected":0}
```

## Time and units

- `ts_ns`: device monotonic clock in nanoseconds; wall-clock이 아닙니다.
- `sector`: 512-byte logical sector unit from block tracepoint.
- `bytes`: request payload bytes.
- latency: host analyzer가 동일 device/request issue-completion을 연결해 계산합니다.

## Integrity

Session close invariant:

```text
events_seen = events_persisted + events_dropped + events_rejected
```

비정상 종료로 footer가 없으면 session은 partial로 취급해야 합니다.
