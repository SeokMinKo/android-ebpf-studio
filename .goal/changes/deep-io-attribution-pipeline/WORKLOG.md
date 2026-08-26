# Worklog — deep-io-attribution-pipeline

## 0001 GOAL — 2026-08-26T23:00:00+09:00

- 요청: 기존 pipeline 개선안에 block I/O의 원본 파일 연결과 상세 debug logging 요구를 합친 구현 스펙 작성.
- 수준/실행/경로: `L3 / DURABLE / DESIGN_FIRST`.
- 권한 경계: Spec과 조사 문서만 작성. production code, release, push는 수행하지 않음.

## 0002 CONTEXT — 2026-08-26T23:05:00+09:00

- Baseline: `10b2d8f`, branch `feature/deep-io-pipeline`.
- 현재 file path는 syscall exit event 처리 후 `/proc/<pid>/fd/<fd>` fallback으로 획득.
- 현재 FileIo와 CompletedIo 사이에는 direct edge가 없음.
- 현재 stderr reader와 drop counter는 장시간 디버깅에 부족함.

## 0003 RESEARCH — 2026-08-26T23:10:00+09:00

- bio split/merge/remap 때문에 DAG 모델 채택.
- buffered writeback과 최초 syscall의 exact 연결은 기본 보장하지 않음.
- UFS actual collector는 target runtime format을 기준으로 tag pairing.
- 상세 내용: `research.md`.

## 0004 SPEC VERIFIED — 2026-08-26T23:20:00+09:00

- Spec revision 1 작성.
- Confirmation: `UNCONFIRMED`; lifecycle: `VERIFIED`.
- 구현 전 사용자 승인과 v0.3 scope 확인 필요.
- 다음 단계: Spec hash와 run-state를 검증하고 사용자에게 승인 요청.

## 0005 CHECKPOINT — 2026-08-26T23:20:00+09:00

- Goal: file-origin을 포함한 deep storage I/O pipeline과 debug contract.
- Done: P0~P3, research@1, spec@1.
- In progress: 없음.
- Next: 사용자 승인 후 P4~P8 design/task/test artifacts 작성.
- Blockers: P3 Spec 작성에는 없음. 구현은 현재 사용자 confirmation 후 시작하며 target kernel evidence는 v0.4/v0.5 전에 필요.
- Working state: Spec artifacts만 새로 생성됨.
- Resume: run-state validator를 실행하고, 승인되면 spec hash를 재확인한 뒤 P4 domain/design부터 시작.

## 0006 CONFIRMATION — 2026-08-26T23:30:00+09:00

- 현재 사용자가 v0.3~v0.5 전체 구현을 요청함.
- Spec revision 1을 `CONFIRMED-AUTO / CONFIRMED`로 전환.
- Authority: repository production code와 tests/docs 변경. Release/push와 device 정책 변경은 포함하지 않음.

## 0007 ENV — 2026-08-26T23:31:00+09:00

- Baseline command `cargo test --workspace` 실행 실패: `/bin/bash: cargo: command not found`.
- Classification: ENV.
- 대응: 코드/fixture/static checks를 진행하고 Rust suite는 NOT RUN으로 유지. 대체 toolchain 존재 여부를 확인하며 결과를 통과로 가장하지 않음.

## 0008 DESIGN — 2026-08-26T23:35:00+09:00

- `design@1`, `tasks@1`, `test-plan@1` 작성.
- 구현 순서: protocol → analysis → collector/diagnostics → UI → docs/conformance.

## 0009 RESUME RECONCILIATION — 2026-08-26T21:15:00Z

- Spec revision/hash `spec@1 / e56e3317...c5d7`가 run-state와 일치함을 확인.
- Baseline은 `10b2d8f`, branch는 `feature/deep-io-pipeline`으로 유지됨.
- 실제 working tree가 TSK-001 lease를 넘어 agent/eBPF/desktop/docs까지 통합 수정된 상태임을 확인.
- Classification: workflow ownership mismatch. 변경을 숨기거나 완료로 간주하지 않고, Rust compile evidence가 생길 때까지 어떤 task도 done으로 닫지 않음.

## 0010 IMPLEMENTATION CHECKPOINT — 2026-08-26T21:20:00Z

- Protocol v4 graph에 transaction ownership, multi-origin, edge confidence, inclusive/exclusive/critical-path/unaccounted와 cohort RCA를 구현.
- lower-stack `stage_key`를 block transaction key와 분리하고 SCSI/UFS/FS runtime tracepoint layout adapter를 추가.
- file identity/path snapshot fallback, 자동 artifact/session 경로, structured host/agent logs, rotation/redaction/bundle, Diagnostics UI를 통합.
- Pipeline/Explorer/Summary/File/Block UI와 CSV/NDJSON export에 attribution과 graph evidence를 연결.

## 0011 CORRELATION AND INTEGRITY HARDENING — 2026-08-26T21:24:00Z

- UFS/SCSI opcode와 completion status를 trace format → eBPF → protocol pairing → waterfall까지 보존.
- 재사용 stage key는 begin을 덮어쓰지 않고 pair 전체를 거부하며 reuse/unmatched/expiry debug code를 기록.
- kernel pointer/tag는 session별 opaque ID로 변환. controller identity 없는 UFS tag-only span은 `Probable`로 제한.
- Stop 시 stdout/stderr drain 완료 전 session writer가 닫히던 경로를 수정하고 agent footer의 실제 graceful 값을 보존.
- Diagnostic bundle에 redacted device profile, capability/attach plan, log level, sequence/footer/counter context를 추가.

## 0012 VERIFICATION BLOCKED — 2026-08-26T21:25:20Z

- `git diff --check`, run-state JSON parsing, spec hash, v0.5.0 version consistency는 성공.
- `cargo fmt`, clippy, workspace tests, Windows GUI check는 모두 `cargo: command not found`로 exit 127.
- Classification: `ENV`. Assertion-level Green과 compile proof가 없으므로 v0.3~v0.5 완료/SATISFIED를 주장하지 않음.
- 추가 미검증: Android verifier/SELinux/vendor tracepoint layout, target-device overhead, Windows rendered UI.
- Resume: Rust 1.98 toolchain이 있는 환경에서 fmt → clippy → tests → GUI → Android agent/eBPF 순으로 실행하고 실패를 수정한 뒤 실제 Phone 검증을 수행.

## 0013 RELEASE AUTHORITY AND NON-SEMANTIC SPEC CLEANUP — 2026-08-26T21:35:00Z

- 현재 사용자가 public GitHub repository push와 v0.5.0 Release 게시를 명시적으로 요청함.
- Git diff gate가 보고한 Markdown trailing whitespace/EOF blank만 제거함. 요구사항 의미는 변경되지 않았으므로 downstream artifacts는 current 상태를 유지함.
- Spec SHA-256을 `6b596a1c...c7aff`로 갱신함.
- 배포 순서: feature branch CI → 오류 수정/재검증 → main 반영 → v0.5.0 Release workflow.
