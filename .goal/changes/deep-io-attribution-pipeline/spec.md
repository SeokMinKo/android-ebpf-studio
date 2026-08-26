---
change_id: deep-io-attribution-pipeline
revision: 1
level: L3
execution_mode: DURABLE
route: DESIGN_FIRST
confirmation: CONFIRMED-AUTO
lifecycle: CONFIRMED
confirmed_by: current user implementation request on 2026-08-26
baseline: 10b2d8f (v0.2.0 feature branch)
---

# Deep I/O Attribution & Pipeline Specification

## 1. 문서 목적

Android eBPF Storage Studio가 Android Phone의 한 I/O를 파일 기원부터 VFS, 파일시스템, bio, Block, SCSI, UFS까지 추적하고, 각 구간의 지연과 연결 근거를 Windows UI에서 설명할 수 있도록 하는 구현 계약이다.

이 문서는 구현 기준선이다. 현재 상태는 `CONFIRMED / CONFIRMED-AUTO`이며, 사용자의 v0.3~v0.5 전체 구현 요청 범위에서 production code 변경을 허용한다.

## 2. 문제와 현재 동작

- [Repo evidence] v0.2.0은 `raw_syscalls`의 read/write 진입·종료를 수집하고, agent가 이벤트를 받은 뒤 `/proc/<pid>/fd/<fd>`를 읽어 경로를 기록한다.
- [Repo evidence] `FileIo`와 `CompletedIo`는 서로 독립적으로 저장되며, syscall 파일 정보가 block request에 직접 연결되지 않는다.
- [Repo evidence] 실제 장비에서 보장된 파이프라인 계층은 syscall과 generic block이다. SCSI/UFS/F2FS/ext4는 capability inventory와 simulator 표현 중심이다.
- [Repo evidence] pipeline correlation은 request ID 또는 시간·sector·bytes·thread 근접성으로 평면 span을 선택한다. bio split/merge와 다중 원인을 표현하는 그래프는 없다.
- [Repo evidence] collector의 `kernel_drops`는 현재 항상 0이며, stderr는 host에서 최대 16 KiB 한 번만 읽으므로 장시간 디버깅 정보가 유실될 수 있다.
- [User] 사용자는 각 block I/O가 어느 파일에서 시작됐는지, 계층별로 몇 ms가 걸렸는지, 파일시스템 내부 breakdown과 상세 디버그 로그를 원한다.

## 3. 목표와 성공 신호

1. 지원되는 단말에서 한 I/O를 `File operation → VFS/FS → bio → block request → SCSI → UFS`의 방향성 그래프로 표현한다.
2. block request마다 0개, 1개 또는 여러 개의 파일 origin을 연결하고, 각 연결의 근거와 신뢰도를 표시한다.
3. 실측, 파생 계산, 시간적 컨텍스트, 미지원 상태를 UI와 export에서 구분한다.
4. inclusive, exclusive, queue, service, critical-path, unaccounted 시간을 중복 없이 계산한다.
5. capture가 실패하거나 연결률이 낮을 때 developer가 로그와 diagnostic bundle만으로 attach, decode, drop, correlation, TTL, schema 문제를 재현할 수 있게 한다.

## 4. 프로젝트 측정 원칙

이 변경과 후속 구현은 다음 원칙을 따라야 한다.

- **MEASURED-TRUTH:** 관측되지 않은 계층은 `0 ms`가 아니라 `Unavailable`이어야 한다.
- **EDGE-EVIDENCE:** 신뢰도는 transaction 전체가 아니라 각 연결 edge에 부여해야 한다.
- **NO-FORCED-ATTRIBUTION:** 유일하지 않은 파일 또는 요청 후보를 임의로 하나 선택하지 않아야 한다.
- **PORTABLE-PROBE:** vendor kernel offset을 하드코딩하지 않고 tracefs format/BTF/runtime capability로 attach plan을 결정해야 한다.
- **BOUNDED-OVERHEAD:** kernel map, host queue, 로그 파일, 진단 필드의 크기와 수명은 제한되어야 한다.
- **DEBUGGABLE-BY-DESIGN:** 모든 주요 상태 전이와 폐기 결정은 안정된 코드 및 correlation context로 진단 가능해야 한다.
- **BACKWARD-READABLE:** 새 reader는 v1~v3 session을 계속 읽어야 하며, 없는 필드는 unavailable로 해석해야 한다.

## 5. 범위

### 포함

- Protocol v4와 이전 session 호환 reader
- 안정된 파일 정체성, 경로 스냅샷, I/O origin 분류
- syscall/VFS/FS/bio/block/SCSI/UFS 노드와 edge 기반 transaction graph
- bio split/merge, request merge, partial completion, ID/tag reuse 방어
- F2FS/ext4/page-cache/writeback/readahead의 capability-driven breakdown
- per-edge confidence와 correlation evidence
- inclusive/exclusive/critical-path/unaccounted 계산
- 파일·inode·origin 기준 UI filter/group/summary/export
- host/agent/eBPF 계층의 구조화된 debug logging, health metric, diagnostic bundle
- 자동 artifact/session/debug-log 경로

### 제외

- 상용 `user` build의 root/BPF 제한 우회
- SELinux 또는 kernel image 자동 변경
- UFS controller firmware 내부 또는 NAND media 내부 시간을 tracepoint 없이 추정
- 모든 buffered writeback을 최초 write syscall과 exact하게 연결
- UIC context marker를 command latency에 강제로 더하기
- 암호화 전 파일명이나 앱 데이터 내용을 읽는 기능
- 원격 telemetry 업로드

### 변경 금지 표면

- 사용자 승인 없는 device 설정/SELinux/kernel 변경
- session 또는 진단 로그의 외부 전송
- kernel hot path에서 경로 문자열 조립 또는 무제한 map 성장

## 6. 핵심 용어와 모델 경계

| 컨텍스트 | 용어 | 코드 이름 | 정의 및 불변식 |
| --- | --- | --- | --- |
| File attribution | File identity | `FileIdentity` | 경로와 분리된 파일 정체성. filesystem device와 inode가 필수이고 mount/inode generation은 지원 시 포함한다. |
| File attribution | Path snapshot | `PathSnapshot` | 특정 시점에 관측한 이름. rename/unlink 후 바뀔 수 있으며 정체성으로 사용하지 않는다. |
| Transaction | Node | `IoNode` | syscall, VFS, FS, bio, request, SCSI, UFS, UIC 중 하나의 관측 단위다. |
| Transaction | Edge | `IoEdge` | 두 노드의 인과 또는 구조 관계이며 자체 confidence와 evidence를 가진다. |
| Transaction | Origin | `IoOrigin` | file, filesystem metadata, journal, GC, writeback, readahead, swap, unknown 중 하나다. |
| Measurement | Span | `MeasuredSpan` | 시작과 종료가 실제 이벤트로 관측된 구간이다. |
| Measurement | Context | `ContextMarker` | 시간적으로 관련 있으나 additive latency가 아닌 상태 변화다. |
| Analysis | Critical path | `CriticalPath` | transaction completion을 결정하는 방향성 경로다. |

### 모델 불변식

- `INV-001`: `PathSnapshot`만으로 block request와 file을 `Exact`로 연결해서는 안 된다.
- `INV-002`: 하나의 block request는 여러 origin edge를 가질 수 있으며, 다중 origin을 한 파일로 축약해서는 안 된다.
- `INV-003`: graph는 시간 방향의 DAG여야 한다. cycle 또는 종료가 시작보다 이른 span은 거부하고 진단 이벤트를 남긴다.
- `INV-004`: `ContextOnly` node/edge는 accounted 또는 exclusive latency에 포함하지 않는다.
- `INV-005`: inclusive 구간의 합이 아닌 interval union과 critical path로 시간을 계산해 중복 합산을 방지한다.
- `INV-006`: pointer, tag, fd 같은 재사용 가능한 key는 boot/session scope와 lifetime/TTL 검증 없이 재사용하지 않는다.
- `INV-007`: 값이 미관측·미지원·유실된 경우 0으로 직렬화하거나 표시하지 않는다.

## 7. 기능 요구사항

### 7.1 Capability와 attach plan

| ID | 요구사항 | 출처 | 우선순위 | 상태 |
| --- | --- | --- | --- | --- |
| REQ-001 | capture 전 agent는 tracefs event format, BTF, attach 방식, 필수 field를 검사하여 계층별 `Measured / Derived / Context / Unavailable` 계획을 출력해야 한다. | [User]+[Repo evidence] | Must | ADDED |
| REQ-002 | attach plan은 각 probe의 선택 이유, 대체 후보, field layout hash, 성공/실패 코드와 제한을 기록해야 한다. | [User] | Must | ADDED |
| REQ-003 | probe는 우선 static tracepoint, 다음 BTF 기반 fentry/fexit 또는 fprobe, 마지막으로 승인된 kprobe/kretprobe fallback을 사용해야 한다. 지원되지 않으면 계층을 unavailable로 남겨야 한다. | [External source] | Must | ADDED |
| REQ-004 | capability profile은 build fingerprint, kernel release, boot ID와 연결해 session에 보존하되 vendor offset을 source code에 하드코딩하지 않아야 한다. | [Repo evidence] | Must | ADDED |

### 7.2 파일 정체성과 경로

| ID | 요구사항 | 출처 | 우선순위 | 상태 |
| --- | --- | --- | --- | --- |
| REQ-010 | file operation은 `pid/tid/fd`, operation, requested/completed bytes, file offset(지원 시), `FileIdentity`, `PathSnapshot`, path source와 capture timestamp를 기록해야 한다. | [User] | Must | ADDED |
| REQ-011 | VFS probe에서 `struct file`을 읽을 수 있는 단말은 filesystem device와 inode를 직접 수집해 `FileIdentity`를 생성해야 한다. | [User] | Must | ADDED |
| REQ-012 | 직접 identity 수집이 불가능하면 `/proc/<pid>/fd/<fd>` 경로 해석을 fallback으로 사용하되 confidence를 `Attributed` 이하로 제한하고 FD 재사용/프로세스 종료 실패를 구분해야 한다. | [Repo evidence] | Must | MODIFIED |
| REQ-013 | rename/unlink가 발생해도 identity와 path snapshot을 분리하여, UI에 `deleted`, path source, snapshot 시점을 표시해야 한다. | [Assumption] | Should | ADDED |
| REQ-014 | path를 얻지 못해도 inode identity가 있으면 파일별 집계가 가능해야 하며 UI는 `<inode dev:ino>` 형태의 안정된 fallback label을 제공해야 한다. | [User] | Must | ADDED |
| REQ-015 | 앱 package name은 PID→UID/package 해석이 유일할 때 별도 attribution으로 제공하고 file identity를 대체하지 않아야 한다. | [Assumption] | Could | ADDED |

### 7.3 File-to-block 상관관계

| ID | 요구사항 | 출처 | 우선순위 | 상태 |
| --- | --- | --- | --- | --- |
| REQ-020 | engine은 file operation, VFS/FS span, bio, block request를 node로 만들고 직접 관측된 pointer/ID propagation을 edge로 보존해야 한다. | [User] | Must | ADDED |
| REQ-021 | 동일 task context에서 file identity가 bio submission까지 직접 전달되고 key lifetime이 검증되면 file→bio edge를 `Exact`로 표시할 수 있다. | [Assumption] | Must | ADDED |
| REQ-022 | sector/bytes/op/time/thread의 유일 후보 matching은 `Probable`만 허용하며 후보가 2개 이상이면 연결하지 않아야 한다. | [Repo evidence] | Must | MODIFIED |
| REQ-023 | bio split, front/back merge, remap과 bio→request merge를 1:N/N:1 edge로 표현해야 한다. | [External source] | Must | ADDED |
| REQ-024 | 여러 파일의 bio가 하나의 request로 merge되면 모든 file origin을 표시하고, 알려진 경우에만 origin별 byte contribution을 표시해야 한다. | [User] | Must | ADDED |
| REQ-025 | buffered writeback은 inode/page/bio에서 직접 identity를 얻은 경우 해당 파일의 device I/O임을 Exact로 표현할 수 있지만, 최초 write syscall과의 edge는 직접 causation token이 없으면 `ProbableAsync`여야 한다. | [External source] | Must | ADDED |
| REQ-026 | metadata, journal, F2FS GC, checkpoint, readahead가 만든 I/O는 해당 system origin으로 표시하며 존재하지 않는 사용자 파일 path를 만들지 않아야 한다. | [User] | Must | ADDED |
| REQ-027 | unmatched, ambiguous, expired, duplicate/reused key와 out-of-order edge는 reason code와 함께 집계하고 분석 데이터에서 조용히 버리지 않아야 한다. | [User] | Must | ADDED |

### 7.4 계층별 파이프라인

| ID | 요구사항 | 출처 | 우선순위 | 상태 |
| --- | --- | --- | --- | --- |
| REQ-030 | 지원 단말에서 Syscall, VFS, Filesystem, Page Cache/Writeback, Bio, Block Queue, Block Device, SCSI, UFS를 request graph에 표현해야 한다. | [User] | Must | ADDED |
| REQ-031 | UFS `SEND`와 `COMPLETE`는 controller/device와 tag lifetime을 검증해 pair하고 LBA, transfer length, opcode, status를 보존해야 한다. | [External source] | Must | ADDED |
| REQ-032 | SCSI start/done은 직접 command/request identity가 있을 때만 Exact이며, field matching만 가능한 경우 Probable로 제한해야 한다. | [User] | Must | ADDED |
| REQ-033 | UIC power mode, Hibern8, gear/lane, reset/error는 command key가 없으면 `ContextOnly` marker로 표시하고 additive latency에서 제외해야 한다. | [User] | Must | ADDED |
| REQ-034 | F2FS는 지원되는 probe 범위에서 data/node/meta, allocation, foreground/background GC, checkpoint, flush를 구분해야 한다. | [User] | Should | ADDED |
| REQ-035 | ext4는 지원되는 probe 범위에서 extent lookup, delayed allocation, journal/commit, writeback, metadata update를 구분해야 한다. | [User] | Should | ADDED |
| REQ-036 | page-cache hit read처럼 block node가 없는 정상 I/O도 완전한 file transaction으로 표시하고 `device I/O 없음`을 오류로 취급하지 않아야 한다. | [External source] | Must | ADDED |

### 7.5 시간 계산과 분석

| ID | 요구사항 | 출처 | 우선순위 | 상태 |
| --- | --- | --- | --- | --- |
| REQ-040 | 각 span에 inclusive와 exclusive duration을 제공해야 하며 exclusive는 parent interval에서 additive child interval union을 뺀 값이어야 한다. | [User] | Must | ADDED |
| REQ-041 | transaction별 critical path와 critical-path contribution을 계산하고 waterfall에서 강조해야 한다. | [User] | Must | ADDED |
| REQ-042 | unaccounted interval은 `probe_unavailable`, `event_lost`, `ambiguous`, `clock_invalid`, `vendor_internal`, `unknown` reason으로 나눠야 한다. | [User] | Must | ADDED |
| REQ-043 | logging/busy/idle은 monotonic clock을 사용하고 busy는 선택 범위의 completed block interval union으로 계산하는 기존 의미를 유지해야 한다. | [Repo evidence] | Must | UNCHANGED |
| REQ-044 | p50/p95/p99와 Read/Write × Sequential/Random × Small/Large 분류를 유지하고 file/origin/layer/confidence 기준 grouping을 추가해야 한다. | [User] | Must | MODIFIED |

### 7.6 UI와 export

| ID | 요구사항 | 출처 | 우선순위 | 상태 |
| --- | --- | --- | --- | --- |
| REQ-050 | Pipeline과 Block events에 `File/Origin` 열을 추가하고 다중 origin은 개수와 펼침 목록으로 표시해야 한다. | [User] | Must | ADDED |
| REQ-051 | transaction 선택 시 node/edge graph, waterfall, file identity/path snapshot, 연결 근거와 confidence를 함께 보여줘야 한다. | [User] | Must | ADDED |
| REQ-052 | X/Y axis와 Group By 후보에 file, inode, origin, layer latency, critical-path contribution, edge confidence를 추가해야 한다. | [User] | Must | MODIFIED |
| REQ-053 | Summary는 기존 category 외에 file/origin별 I/O count, bytes, latency percentile, attributed/exact/probable/unattributed 비율을 제공해야 한다. | [User] | Must | ADDED |
| REQ-054 | 모든 graph/table 선택과 time range는 상호 cross-filter되고 pan/zoom 상태를 유지해야 한다. | [User] | Should | ADDED |
| REQ-055 | “Why slow?”는 median cohort 대비 queue/service/FS/writeback/UFS 증가분과 근거 confidence를 설명하고, 근거 없는 원인을 단정하지 않아야 한다. | [User] | Should | ADDED |
| REQ-056 | NDJSON/CSV export는 file identity, path snapshot metadata, nodes, edges, evidence, confidence, origin과 unaccounted reason을 손실 없이 포함해야 한다. | [User] | Must | ADDED |

### 7.7 디버그 로그와 진단

| ID | 요구사항 | 출처 | 우선순위 | 상태 |
| --- | --- | --- | --- | --- |
| REQ-060 | measurement stdout NDJSON과 diagnostic stderr JSONL을 분리하고, host는 둘을 별도 파일에 지속적으로 drain해야 한다. | [User]+[Repo evidence] | Must | ADDED |
| REQ-061 | host log는 `%LOCALAPPDATA%/AndroidEbpfStudio/logs/<session-id>/host.jsonl`, agent log는 같은 폴더의 `agent.jsonl`에 자동 저장해야 한다. | [User] | Must | ADDED |
| REQ-062 | 기본 로그 레벨은 INFO이며 GUI에서 해당 session만 DEBUG/TRACE로 높일 수 있어야 한다. TRACE의 per-event 결정 로그는 명시적으로 켜야 한다. | [User] | Must | ADDED |
| REQ-063 | 로그는 최소 `schema_version, ts, level, component, event, session_id, boot_id, outcome, code`와 적용 가능한 correlation/node/probe/duration/count context를 가져야 한다. | [User] | Must | ADDED |
| REQ-064 | attach, layout parsing, map 설정, verifier/SELinux 실패, decode rejection, sequence gap, drops, correlation decision, collision, TTL expiry, graph rejection, footer integrity, export 실패를 안정된 event name과 code로 기록해야 한다. | [User] | Must | ADDED |
| REQ-065 | health record는 probe별 event count, pair 성공/실패, ambiguous/expired/reused key, ring reserve failure, host queue high-water mark, decode rejection과 output write failure를 누적 counter로 제공해야 한다. | [User] | Must | ADDED |
| REQ-066 | `kernel_drops`를 알 수 없으면 0이 아닌 `null/unavailable`로 표현해야 하고 실제 ring reserve failure counter가 있으면 그 값을 사용해야 한다. | [Repo evidence] | Must | MODIFIED |
| REQ-067 | Diagnostics UI는 level/component/code/session/correlation으로 filter하고 관련 transaction으로 이동할 수 있어야 한다. | [User] | Should | ADDED |
| REQ-068 | `Export diagnostic bundle`은 version/build, redacted device profile, capability, attach plan, trace format/layout hashes, host/agent logs, health/footer, 설정을 포함하고 raw session과 full path는 사용자가 선택한 경우에만 포함해야 한다. | [User] | Must | ADDED |
| REQ-069 | host panic/agent abnormal exit 시 마지막 상태, child exit status, footer 존재 여부, 마지막 sequence와 resume/reproduction command를 기록해야 한다. | [User] | Must | ADDED |

## 8. 데이터 계약 초안 — Protocol v4

v4는 v3 record envelope를 유지하고 다음 typed event를 추가한다. 알 수 없는 field는 무시하며 알 수 없는 record type은 기존 규칙대로 rejection으로 계산한다.

```rust
struct FileIdentity {
    fs_device_major: u32,
    fs_device_minor: u32,
    inode: u64,
    inode_generation: Option<u32>,
    mount_id: Option<u64>,
}

struct PathSnapshot {
    path: Option<String>,
    source: PathSource,       // bpf_d_path | proc_fd | inode_only | unavailable
    captured_ts_ns: u64,
    deleted: bool,
}

struct IoNode {
    node_id: u64,
    kind: IoNodeKind,
    start_ts_ns: u64,
    end_ts_ns: Option<u64>,
    origin: IoOrigin,
    file: Option<FileIdentity>,
    path: Option<PathSnapshot>,
    attributes: BoundedAttributes,
}

struct IoEdge {
    edge_id: u64,
    from_node_id: u64,
    to_node_id: u64,
    relation: IoRelation,
    confidence: EdgeConfidence,
    evidence: Vec<CorrelationEvidence>,
}
```

`EdgeConfidence`는 다음 순서를 갖는다.

- `Exact`: 동일 pointer/tag 또는 직접 전파된 stable ID이며 lifetime 충돌이 없다.
- `Probable`: 유일 후보이지만 dev/sector/bytes/op/time/thread 같은 간접 증거를 사용했다.
- `ProbableAsync`: 같은 file identity의 writeback/readahead이나 최초 syscall과 직접 token이 없다.
- `ContextOnly`: 원인 관계 없이 같은 시간창의 상태 변화다.
- `Unattributed`: 연결을 만들지 못했다. edge를 위조하지 않고 counter/reason으로 남긴다.

`CorrelationEvidence`는 raw pointer를 export하지 않고 session-local opaque ID, match type, delta time, 범위 일치 여부, 후보 수를 포함한다.

### 호환성

- v1~v3 reader 유지.
- v3 `FileIo.path`는 v4 import 시 `PathSource::ProcFd`, identity unknown으로 변환한다.
- v3 pipeline span은 독립 node로 변환하고 edge가 없음을 명시한다.
- v4 writer만 새 graph/event를 기록한다. downgrade writer는 제공하지 않는다.

## 9. 상관관계 계약

### CON-001 — File operation 생성

- Preconditions: 지원 syscall/VFS 이벤트, 유효한 monotonic timestamp.
- Postconditions: 고유 node ID, operation, task, byte count와 가능한 identity/path snapshot이 생성된다.
- Failure: FD/path/inode 해석 실패는 operation 자체를 버리지 않고 classified missing field로 남긴다.
- Atomicity: node emission과 kernel map cleanup은 재사용 key가 새 operation에 누출되지 않도록 해야 한다.

### CON-002 — Edge 생성

- Preconditions: 두 node가 같은 boot/session에 있고 시간과 key lifetime이 유효하다.
- Postconditions: edge는 evidence와 confidence를 가지며 후보 수가 기록된다.
- Failure: 다중 후보, key reuse, TTL expiry, 역방향 시간은 edge를 만들지 않고 reason counter/log를 남긴다.
- Idempotency: 동일 evidence의 재처리는 같은 logical edge 하나만 만든다.

### CON-003 — 시간 계산

- Preconditions: 유효한 DAG와 monotonic span.
- Postconditions: inclusive/exclusive/accounted/unaccounted/critical path가 중복 없이 계산된다.
- Failure: invalid graph/span은 transaction 전체를 crash시키지 않고 해당 항목을 격리한다.

### CON-004 — 진단 로그

- Preconditions: session ID가 capture 시작 전에 생성된다.
- Postconditions: host와 agent의 lifecycle, attach, health, failure를 session ID로 join할 수 있다.
- Failure: 로그 쓰기 실패는 capture data stream에 text를 섞지 않고 GUI warning과 in-memory counter로 알린다.
- Data safety: token, credential, raw payload를 기록하지 않고 serial은 기본 hash, full path는 measurement session에만 존재한다.

## 10. 관측 가능성 계약

### OBS-001 — `capture.lifecycle`

- 질문: capture가 어느 단계에서 왜 중단됐는가?
- 상태: `created → preflight → deploying → attaching → capturing → stopping → completed|failed`.
- 필드: session/boot/build, state.from/to, duration, outcome, stable code, child exit/footer/last sequence.

### OBS-002 — `probe.attach`

- 질문: 어떤 probe와 field layout을 선택했고 왜 attach에 실패했는가?
- 필드: layer, probe kind/name, trace format hash, required/optional fields, fallback rank, verifier summary, errno, outcome.
- 제한: verifier log는 크기를 제한해 별도 attachment로 저장하고 UI log에는 요약만 기록한다.

### OBS-003 — `correlation.decision`

- 질문: 파일과 block request가 왜 연결되거나 거부됐는가?
- 기본 INFO: 1초 health aggregate만 기록한다.
- DEBUG: ambiguous, reuse, expiry, invalid edge를 개별 기록한다.
- TRACE: 명시적으로 켠 경우에만 성공 edge의 bounded evidence를 기록한다.
- 필드: opaque node IDs, relation, confidence, candidate count, delta, match flags, reason code.

### OBS-004 — `stream.health`

- 질문: 측정 결과가 drops 또는 decode 문제로 왜곡됐는가?
- 필드: probe별 emitted, reserve failures, host received/persisted/rejected, sequence gaps, queue high-water, pair ratio counts, graph rejection, log write failure.
- 규칙: 실패와 drop counter는 sampling하지 않는다.

### OBS-005 — `session.integrity`

- 질문: session이 완전하고 재분석 가능한가?
- 규칙: 정상 종료 시 `seen = persisted + dropped + rejected`를 검사한다. 불일치 또는 footer 부재는 partial 상태와 code를 남긴다.

### 로그 보존과 제한

- 기본 회전: 파일당 20 MiB, host/agent 각각 최근 5개 파일.
- INFO 성공 이벤트는 상태 전이와 주기 health 중심이며 per-I/O 성공 로그를 남기지 않는다.
- WARN/ERROR 및 drop/integrity 이벤트는 sampling하지 않는다.
- free-form error text는 최대 4 KiB로 제한하고 stable code를 별도 필드로 유지한다.
- metric label에는 raw path, inode, PID, request ID를 넣지 않는다.

## 11. UI 동작 예

### SCN-001 — Direct read의 파일부터 UFS까지 Exact 경로

Given VFS file identity, bio pointer, request pointer와 UFS tag를 직접 관측한 단말에서 128 KiB direct read가 실행되고
When transaction을 선택하면
Then 파일 path snapshot과 identity, VFS/FS/bio/block/SCSI/UFS node가 보이고 각 direct edge는 Exact 근거를 표시한다.

### SCN-002 — 두 파일이 하나의 block request로 merge

Given file A와 B의 bio가 하나의 block request로 merge되고
When request row와 pipeline을 열면
Then `2 file origins`가 표시되고 A/B가 모두 펼쳐지며 임의 대표 path 하나로 축약되지 않는다.

### SCN-003 — Buffered writeback

Given write syscall은 먼저 완료되고 같은 inode의 page가 나중에 background writeback으로 제출되며
When 해당 device I/O를 열면
Then file identity→writeback/bio 관계는 직접 증거 범위에서 표시되고 최초 syscall edge는 `ProbableAsync` 또는 Unattributed이며 Exact로 표시되지 않는다.

### SCN-004 — Page-cache hit read

Given read가 page cache에서 완료되어 block event가 없고
When file transaction을 조회하면
Then syscall/VFS/FS 구간은 보이지만 device 구간은 `No device I/O`이며 실패 또는 0 ms device latency로 표시되지 않는다.

### SCN-005 — 애매한 시간 기반 후보

Given 같은 sector/bytes/op 시간창에 두 개의 file operation 후보가 있고 direct key가 없으며
When correlator가 평가하면
Then file edge를 생성하지 않고 `ambiguous_candidates=2` counter와 debug reason을 남긴다.

### SCN-006 — Attach 실패 진단

Given UFS event format은 발견됐지만 필수 tag field를 해석할 수 없고
When capture를 시작하면
Then generic block capture는 계속되고 UFS는 unavailable로 표시되며 attach plan, field hash와 `UFS_LAYOUT_UNSUPPORTED`가 diagnostic bundle에 남는다.

### SCN-007 — Debug log의 데이터 안전성

Given 기본 INFO logging으로 개인 앱 파일을 읽고
When host/agent JSONL을 검사하면
Then raw path, raw device serial, payload는 없고 session/correlation context와 stable code만 존재한다.

## 12. 비기능 요구사항

| ID | 제약 | 검증 |
| --- | --- | --- |
| NFR-001 | 모든 kernel correlation map은 maximum entries와 TTL cleanup을 가져야 한다. | map definition inspection + saturation test |
| NFR-002 | default INFO에서는 per-I/O diagnostic disk write를 하지 않아야 한다. | high-volume simulated capture log-count test |
| NFR-003 | host는 stdout/stderr를 동시에 drain하여 한 stream의 backpressure가 다른 stream을 막지 않아야 한다. | dual-stream integration test |
| NFR-004 | 1 MiB 초과 measurement line과 설정된 한도를 넘는 diagnostic field는 거부/절단하고 counter를 증가시켜야 한다. | boundary tests |
| NFR-005 | protocol timestamp는 device monotonic ns를 유지하며 host wall-clock은 별도 필드여야 한다. | serialization/clock-domain tests |
| NFR-006 | 100,000개 이상 node가 있는 session에서도 UI는 전체 복사 없이 window/aggregation을 사용해야 하며, 실제 목표 frame time은 benchmark baseline을 먼저 측정한 뒤 revision 2에서 확정한다. | benchmark spike; 현재 수치 기준은 BLOCKED |
| NFR-007 | debug logs는 기본 설정에서 component별 100 MiB를 초과하지 않아야 한다. | rotation integration test |
| NFR-008 | v1~v3 fixture를 v4 reader가 panic 없이 읽고 없는 graph/file identity를 unavailable로 반환해야 한다. | compatibility tests |
| NFR-009 | 실제 capture overhead는 `Off / Balanced / Deep` 모드별 동일 workload A/B 결과와 event/drop rate를 release evidence로 남겨야 한다. 고정 성능 한계는 대상 단말 baseline 확보 후 확정한다. | device benchmark; 현재 수치 기준은 BLOCKED |

## 13. 분석/프로브 설계 결정

| ID | 결정 | 근거와 대안 |
| --- | --- | --- |
| DEC-001 | 평면 span 배열 대신 typed node/edge DAG를 사용한다. | split/merge, 다중 파일, async writeback은 선형 파이프라인으로 표현할 수 없다. |
| DEC-002 | file identity와 path snapshot을 분리한다. | path는 rename/unlink/alias로 변하지만 inode 기반 identity는 해당 관측 수명 동안 안정적이다. |
| DEC-003 | direct pointer/tag propagation만 Exact로 인정한다. | 시간·sector matching은 충돌 가능성이 있어 Probable 이상의 근거가 아니다. |
| DEC-004 | UIC는 직접 command key가 없으면 context lane으로 둔다. | 링크 상태 이벤트를 개별 I/O service time으로 합산하면 중복 또는 허위 latency가 된다. |
| DEC-005 | typed kernel events와 userspace graph builder를 분리한다. | kernel hot path는 bounded capture만 담당하고 복잡한 후보 평가, path display, graph validation은 agent/desktop에서 수행한다. |
| DEC-006 | diagnostics는 stderr JSONL, measurements는 stdout NDJSON로 분리한다. | 기존 protocol reader와 session integrity를 지키면서 attach/verifier/correlation 정보를 장시간 보존한다. |
| DEC-007 | probe profile은 capability-driven adapter로 구현한다. | Android vendor kernel 간 event/function/layout 차이를 한 object의 하드코딩으로 안전하게 흡수할 수 없다. |

## 14. 단계별 제공 범위

### v0.3 — Attribution & Correlation Foundation

- Protocol v4 compatibility
- 구조화 debug logging과 diagnostic bundle
- stable file identity/path snapshot
- File/VFS/bio/block graph와 다중 origin
- confidence/evidence UI 및 file 기준 filter/summary
- actual drop/reserve/correlation health counters

### v0.4 — Real Lower Stack

- SCSI start/done actual collector
- UFS command SEND/COMPLETE actual collector
- SCSI↔UFS edge와 UIC context
- capability/attach-plan UI와 device profile cache

### v0.5 — Filesystem Deep Dive & RCA

- F2FS/ext4 profile과 subspan
- page-cache hit/miss, readahead, dirty/writeback causality
- inclusive/exclusive/critical path
- median/p99 cohort 비교와 “Why slow?”
- session A/B diff

각 버전은 미지원 계층을 unavailable로 표시하는 상태로 독립 배포 가능해야 한다.

## 15. 검증과 traceability 계획

| Spec IDs | 계획된 테스트 | 증명 경계 | 예상 RED |
| --- | --- | --- | --- |
| REQ-010~014, INV-001 | file identity/path fixture 및 FD reuse test | protocol + agent parser | 현재 `FileIo`에 identity/snapshot source가 없음 |
| REQ-020~027, INV-002/006 | split/merge/multi-origin/ambiguity graph tests | protocol analysis core | 현재 graph/edge model이 없음 |
| REQ-030~036 | synthetic SCSI/UFS/FS trace format fixtures | agent capability/decoder | 현재 inventory만 있고 actual events 없음 |
| REQ-040~044, INV-003~005 | nested/overlap/branch critical-path tests | analysis core | 현재 exclusive/critical path가 없음 |
| REQ-050~056 | deterministic simulator UI acceptance | desktop public UI state | 현재 block row와 graph에 file edge가 없음 |
| REQ-060~069, NFR-002~007 | dual stream, rotation, redaction, crash tests | agent process + desktop capture | 현재 stderr 일회 16 KiB read 및 file sink 없음 |
| NFR-008 | stored v1/v2/v3 fixtures | session reader | backward reader는 있으나 v4 import 규칙 없음 |
| NFR-009 | adb-connected repeatable workload | real device | 대상 단말 baseline 미확보 |

구현 시작 후 working suite는 대상 crate test이며 commit suite는 다음을 사용한다.

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo check -p android-ebpf-studio --features gui
```

eBPF object와 실제 단말 검증은 별도 evidence로 분리하며 host unit test를 실제 verifier/tracepoint 증거로 가장하지 않는다.

## 16. 위험, 중단 및 rollback

| 위험 | 지표 | 완화 | 중단/rollback |
| --- | --- | --- | --- |
| vendor field/layout 차이 | layout parse/attach failure | runtime profile과 fallback | 해당 계층만 unavailable; generic block 유지 |
| 잘못된 file attribution | ambiguous/reuse 증가 | edge evidence와 no-forced rule | Probable edge 비활성화 옵션, raw nodes 유지 |
| map pressure/overhead | reserve failure, CPU/drop 증가 | bounded TTL, capture modes | deep probe 해제 후 Balanced로 재시작 |
| 로그 폭증 | rotation/drop counter | INFO aggregate, bounded rotation | TRACE 자동 해제 및 warning |
| protocol incompatibility | old fixture failure | additive v4 reader | v4 writer 기능 flag rollback, v3 read 유지 |
| UI 대용량 정지 | frame/queue lag | windowing, aggregation | graph detail limit 후 raw export 제공 |

## 17. 열려 있는 질문과 승인 게이트

1. **Target kernel evidence:** 실제 목표 Phone의 UFS/SCSI/F2FS/ext4 tracepoint `format`, BTF와 함수 목록이 필요하다. 이것 없이는 v0.4/v0.5의 정확한 attach profile을 확정할 수 없다.
2. **성능 기준:** NFR-006/NFR-009의 수치 threshold는 대표 단말과 workload baseline 측정 후 revision 2에서 확정해야 한다.
3. **경로 개인정보 기본값:** measurement session에는 현재처럼 full path를 저장하되 diagnostic bundle의 full path/raw session은 opt-in으로 제안한다.

추천 승인 범위는 v0.3부터 순차 구현하는 것이다. v0.4/v0.5는 target capability evidence를 얻은 뒤 세부 probe profile을 delta spec으로 확정한다.

## 18. Definition of Done

- [ ] 모든 Must requirement가 현재 Spec revision과 연결된 실제 test/device evidence를 가진다.
- [ ] file attribution이 Exact/Probable/ProbableAsync/Unattributed 규칙을 위반하지 않는다.
- [ ] split/merge, 다중 origin, FD/tag/request reuse, out-of-order와 partial session 경계 테스트가 통과한다.
- [ ] actual drop과 correlation failure가 health/log/UI에서 일치한다.
- [ ] stdout measurement와 stderr diagnostics가 섞이지 않고 장시간 동시에 drain된다.
- [ ] v1~v3 session compatibility가 유지된다.
- [ ] 실제 target Phone에서 지원 계층과 unavailable 계층을 구분한 evidence가 남는다.
- [ ] Spec, design, tasks, tests, code, diagnostics, docs와 run state가 같은 revision을 가리킨다.
- [ ] critical/high gap과 stale artifact가 없다.

## 19. Revision log

| Revision | 이유 | 변경 | 무효화 | Confirmation |
| --- | --- | --- | --- | --- |
| 1 | 기존 개선안과 file origin/debug 요구 통합 | REQ-001~069, NFR-001~009, INV-001~007 추가 | 없음 | CONFIRMED-AUTO — 2026-08-26 사용자 전체 구현 요청 |
