# Exact file-to-block attribution handoff

## 목적과 현재 상태

이 문서는 다른 개발 환경에서 `Block I/O → file identity/path` 구현을 이어서 검증하기 위한 인수인계 기준입니다.

- Repository: `https://github.com/SeokMinKo/android-ebpf-studio.git`
- Working branch: `feature/exact-file-block-attribution`
- Baseline: `3a70f1bd1b585b5e8daf990b9be9830c7b97a24b`
- Change contract: `.goal/changes/exact-file-block-attribution/spec.md` revision 1
- 구현 상태: host 코드·테스트·eBPF 빌드 완료
- 남은 필수 단계: 실제 rooted userdebug Android 보드의 verifier/load/attach 및 workload 검증

이 브랜치는 파일 경로 문자열을 block layer에서 직접 생성하지 않습니다. 커널에서는 `filesystem device + inode + optional generation/mount` identity와 `bio/request`의 직접 객체 관계를 수집하고, userspace에서 같은 identity의 `PathSnapshot`을 결합합니다. path가 없어도 exact inode identity는 유효합니다.

## 새 환경에서 시작하기

```bash
git clone https://github.com/SeokMinKo/android-ebpf-studio.git
cd android-ebpf-studio
git fetch origin feature/exact-file-block-attribution
git switch --track origin/feature/exact-file-block-attribution
git status --short --branch
```

작업을 재개하기 전에 다음 순서로 읽습니다.

1. 이 문서
2. `.goal/changes/exact-file-block-attribution/spec.md`
3. `.goal/changes/exact-file-block-attribution/design.md`
4. `.goal/changes/exact-file-block-attribution/run-state.json`
5. `docs/DEVICE_RUNBOOK.md`
6. `.goal/changes/exact-file-block-attribution/evidence/ledger.md`

`run-state.json`에서 `TSK-001`~`TSK-005`는 host 검증 완료이며, `TSK-006`만 target-device acceptance로 남아 있어야 합니다. 이미 완료된 구현을 다시 설계하지 말고 보드 evidence부터 수집합니다.

## 구현된 데이터 흐름

```text
vfs_read/write 또는 writeback(address_space.host)
  → FileIdentity를 현재 task에 저장
  → submit_bio에서 bio identity에 결합
  → blk_mq_bio_to_request에서 새 request origin 방출
  → tp_btf/block_bio_frontmerge|backmerge에서 merge origin 추가
  → block_rq_issue/complete의 같은 request identity와 결합
  → agent가 raw pointer를 session-salted opaque ID로 변환
  → RequestOrigin NDJSON
  → transaction graph의 Exact MergedInto edge
  → 같은 FileIdentity의 FileIo/PathSnapshot으로 경로 보강
```

merge adapter는 성공 이후 호출되는 tracepoint만 사용합니다. Linux v5.10의 tracepoint prototype은 `(request_queue *, request *, bio *)`입니다.

- `include/trace/events/block.h`: <https://github.com/torvalds/linux/blob/v5.10/include/trace/events/block.h>
- 성공 후 trace 호출 위치: <https://github.com/torvalds/linux/blob/v5.10/block/blk-merge.c>

`bio_attempt_front_merge/back_merge` 진입 fentry를 사용하면 실패한 merge도 origin으로 잘못 기록할 수 있으므로 사용하면 안 됩니다.

## 주요 코드 위치

| 영역 | 파일 | 확인할 내용 |
| --- | --- | --- |
| Shared ABI | `crates/ebpf-types/src/lib.rs` | `KIND_REQUEST_ORIGIN`, `KernelFileOrigin`, `FileIdentityLayout` |
| eBPF capture | `crates/android-ebpf/src/main.rs` | VFS/writeback, bio/request, success-only merge hooks, bounded maps |
| BTF offset parser | `crates/android-agent/src/btf_layout.rs` | target `/sys/kernel/btf/vmlinux`의 구조체 member offset 해석 |
| Agent loader | `crates/android-agent/src/main.rs` | typed hook attach, capability/fallback, pointer pseudonymization |
| Protocol/analysis | `crates/protocol/src/lib.rs` | `RequestOrigin`, exact graph edge, path snapshot join, cache invalidation |
| Protocol tests | `crates/protocol/tests/graph.rs` | multi-origin, exact precedence, live cache invalidation |
| Serialization tests | `crates/protocol/tests/session.rs` | pointer가 노출되지 않는 NDJSON round trip |
| CSV/session | `crates/desktop/src/session.rs` | `request_origin` CSV export |

## 정확성 및 fallback 계약

다음 조건을 모두 만족한 capture만 exact adapter를 활성화합니다.

1. issue/complete tracepoint가 동일한 `rq` identity를 제공한다.
2. `/sys/kernel/btf/vmlinux`에서 필요한 file/inode/superblock offset을 해석한다.
3. `vfs_read/write`, `submit_bio`, `blk_mq_bio_to_request`가 attach된다.
4. `tp_btf/block_bio_frontmerge`와 `block_bio_backmerge`가 attach된다.

모두 성공하면 capability record가 `exact_file_attribution=true`이고 VFS/Bio plan이 `measured`입니다. 하나라도 실패하면 `EXACT_ATTRIBUTION_ENABLED=0`을 유지하고 기존 block tracepoint 및 syscall/time/task heuristic을 계속 사용합니다. heuristic edge는 `Probable` 또는 `ProbableAsync`이며 `Exact`로 승격하면 안 됩니다.

추가 규칙:

- 한 request는 0..N file origin을 가질 수 있습니다.
- 최대 8개 origin과 한 개의 overflow 표시 record를 보존하며, 초과 시 `incomplete=true`입니다.
- raw kernel pointer는 protocol, CSV, diagnostic에 출력하지 않습니다.
- exact origin이 있으면 같은 request의 heuristic file 후보를 추가하지 않습니다.
- writeback identity가 exact여도 최초 write syscall과의 인과관계는 exact로 주장하지 않습니다.
- filesystem metadata/journal/GC/swap I/O를 임의의 사용자 파일 path로 표시하지 않습니다.

## 빌드와 host 회귀 검증

요구 도구:

- Rust `1.98.0` + rustfmt/clippy
- nightly Rust + `rust-src`
- `bpf-linker` v0.11.0
- Android NDK r27 이상, API 35 arm64 linker

```bash
rustup toolchain install 1.98.0 --profile minimal --component rustfmt,clippy
rustup target add aarch64-linux-android --toolchain 1.98.0
rustup toolchain install nightly --profile minimal --component rust-src
cargo binstall bpf-linker --version 0.11.0

cargo +1.98.0 fmt --all -- --check
cargo +1.98.0 test --workspace --locked
cargo +1.98.0 clippy --workspace --all-targets --locked -- -D warnings
./scripts/build-ebpf.sh
git diff --check
```

Android agent Linux 빌드 예시:

```bash
export ANDROID_NDK_ROOT=/absolute/path/to/android-ndk
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang"
cargo +1.98.0 build --release -p android-ebpf-agent --target aarch64-linux-android --locked
```

산출물:

```text
target/aarch64-linux-android/release/android-ebpf-agent
crates/android-ebpf/target/bpfel-unknown-none/release/android-storage-ebpf
```

현재 전달 시점의 host evidence:

| 검증 | 결과 | 범위 |
| --- | --- | --- |
| `cargo test --workspace --locked` | PASS | protocol, agent, desktop core regression |
| Clippy `-D warnings` | PASS | workspace all targets, 기본 feature |
| Rust format | PASS | workspace와 eBPF manifest |
| Android arm64 `cargo check` | PASS | agent compile; NDK executable link 제외 |
| `./scripts/build-ebpf.sh` | PASS | `bpfel-unknown-none` release object |
| GUI feature check | NOT RUN | dependency `accesskit v0.24.1`을 현재 환경에서 다운로드하지 못함 |
| Android verifier/load/workload | NOT RUN | target board가 연결되지 않음 |

host build 성공은 target kernel verifier와 attach 성공을 증명하지 않습니다.

## 보드 배포 및 acceptance

먼저 `docs/DEVICE_RUNBOOK.md`의 전체 preflight를 실행합니다. 최소 확인 항목은 다음과 같습니다.

```bash
adb devices -l
adb -s SERIAL root
adb -s SERIAL wait-for-device
adb -s SERIAL shell id
adb -s SERIAL shell uname -r
adb -s SERIAL shell test -r /sys/kernel/btf/vmlinux
adb -s SERIAL shell test -r /sys/kernel/tracing/events/block/block_rq_issue/format
adb -s SERIAL shell test -r /sys/kernel/tracing/events/block/block_rq_complete/format
```

배포:

```bash
adb -s SERIAL shell mkdir -p /data/local/tmp/android-ebpf-studio
adb -s SERIAL push target/aarch64-linux-android/release/android-ebpf-agent /data/local/tmp/android-ebpf-studio/agent
adb -s SERIAL push crates/android-ebpf/target/bpfel-unknown-none/release/android-storage-ebpf /data/local/tmp/android-ebpf-studio/storage-ebpf.o
adb -s SERIAL shell chmod 0755 /data/local/tmp/android-ebpf-studio/agent
adb -s SERIAL shell /data/local/tmp/android-ebpf-studio/agent probe
```

실제 exact origin은 `Deep` 또는 `RawAll` mode에서 수집됩니다. 가장 간단한 방법은 Windows GUI에서 capture를 시작하고 mode를 `Deep`으로 선택한 뒤 `Apply live config`를 누르는 것입니다. 수동 agent 실행 시 stdout과 stderr를 분리해 보존합니다.

```bash
adb -s SERIAL shell /data/local/tmp/android-ebpf-studio/agent capture \
  --bpf-object /data/local/tmp/android-ebpf-studio/storage-ebpf.o \
  --session-id exact-file-validation \
  --log-level debug \
  > exact-file-validation.ndjson \
  2> exact-file-validation.agent.jsonl
```

위 예시처럼 redirection을 `adb` 명령 바깥에 두면 파일은 host에 생성됩니다. redirection까지 따옴표 안의 device shell 명령에 넣으면 device에 생성되므로 구분해야 합니다. 측정 stdout과 diagnostic stderr는 섞지 않습니다.

### Workload matrix

| Workload | 목적 | 최소 기대 결과 |
| --- | --- | --- |
| 알려진 파일 sequential read | read identity propagation | 해당 request에 `request_origin`, 동일 dev/inode, exact edge |
| `fio --direct=1` read/write | page cache를 우회한 direct path | direct request origin과 알려진 파일 identity |
| buffered write 후 `sync` | async writeback adapter | `origin=writeback`; path는 snapshot이 있으면 결합 |
| 여러 파일의 동시 작은 I/O | request merge | 같은 request에 서로 다른 두 identity; 발생하지 않으면 미검증으로 유지 |

Toybox `dd` 기본 검증:

```bash
adb -s SERIAL shell "dd if=/dev/zero of=/data/local/tmp/ebpf-file.bin bs=4096 count=256 conv=fsync"
adb -s SERIAL shell "dd if=/data/local/tmp/ebpf-file.bin of=/dev/null bs=4096 count=256"
adb -s SERIAL shell sync
```

### Acceptance 판정

다음을 모두 증거로 보존해야 `TSK-006`을 완료할 수 있습니다.

- capture capability의 `exact_file_attribution=true`
- VFS/Bio essential plan의 `measured`
- verifier/load/attach 오류가 없는 agent stderr와 관련 `dmesg`
- direct read/write의 `request_origin`과 exact graph edge
- buffered writeback의 identity 및 path/미해결 inode 표시
- raw pointer가 아닌 opaque `request_id/origin_id`
- event loss, origin overflow, rejected record 수
- multi-origin 실제 workload 결과 또는 재현 실패를 명시한 미검증 상태

완료 증거는 `.goal/changes/exact-file-block-attribution/evidence/ledger.md`에 exact command, exit/status, raw summary, 장비 profile과 함께 추가합니다. 이후 `run-state.json`의 `TSK-006`과 `GAP-001`을 실제 증거에 맞춰 갱신합니다. multi-origin 또는 writeback 검증이 없으면 전체 change를 `SATISFIED`로 표시하지 않습니다.

## 예상되는 장비별 실패와 다음 조치

| 증상 | 의미 | 다음 확인 |
| --- | --- | --- |
| BTF는 있으나 exact plan이 unavailable | 필수 member 또는 shared request identity 해석 실패 | capability reason, target BTF, block format 보존 |
| merge `tp_btf` attach 실패 | vendor kernel tracepoint prototype/가용성 차이 | target `vmlinux`의 `btf_trace_block_bio_*merge` prototype 확인 |
| `blk_mq_bio_to_request` attach 실패 | 함수가 inline/제거/renamed 되었거나 tracing 제한 | target BTF function 목록과 verifier log 확인 |
| direct I/O만 exact | writeback hook이 없거나 다른 filesystem path 사용 | `write_cache_pages`, F2FS function BTF 존재 여부 확인 |
| inode만 있고 path 없음 | identity는 관측했지만 FD snapshot과 결합되지 않음 | 같은 dev/inode의 `file_io`, rename/unlink, snapshot 시간 확인 |
| `exact_file_attribution=false`이나 block 기록 정상 | 보수적 fallback이 정상 동작 | heuristic confidence가 Exact가 아닌지 확인 |

필수 typed hook 일부만 attach되었을 때 exact enable을 강제로 켜지 마십시오. 지원 범위를 넓히려면 vendor/kernel별 adapter를 추가하고 capability-gated attach 및 실제 장비 증거를 별도로 남깁니다.

## 전달 시점의 제한사항

- 현재 환경에는 Android NDK linker와 target board가 없어 release Android executable link와 device verifier를 실행하지 못했습니다.
- GUI feature check는 네트워크 dependency 다운로드 제한 때문에 완료하지 못했습니다. core/Desktop session 코드는 workspace test에서 통과했습니다.
- 경로는 현재 inode에서 root까지 eBPF가 직접 순회한 결과가 아니라 `/proc/<pid>/fd` snapshot 결합입니다.
- bind mount, rename, unlink, 장시간 지연 writeback에서는 path가 없거나 다른 유효 alias일 수 있습니다. identity와 path snapshot을 동일한 것으로 취급하지 마십시오.
- Linux v5.10 형태와 다른 merge tracepoint prototype을 가진 커널은 현재 exact adapter를 unavailable로 내리고 fallback합니다.

## 안전한 다음 작업 순서

1. branch와 `run-state.json`을 대조하고 clean worktree에서 시작합니다.
2. host gate를 재실행합니다.
3. Android agent와 eBPF object를 빌드합니다.
4. 한 대의 target board에서 preflight와 attach evidence를 먼저 확보합니다.
5. direct read/write를 통과한 뒤 buffered writeback을 검증합니다.
6. 마지막으로 multi-origin merge를 시도합니다.
7. 증거와 제한사항을 먼저 갱신한 뒤에만 `TSK-006` 완료 여부를 판단합니다.
