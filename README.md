# Android eBPF Storage Studio

Windows에서 실행되는 Rust GUI가 `adb root` 가능한 Android Phone에 eBPF collector를 배포하고, block I/O를 실시간 로깅·분석하는 도구입니다.

## 주요 기능

- ADB 장치 검색과 serial 고정
- `adb root`, ABI, Android/kernel 버전, BTF, tracefs, block/UFS event preflight
- Android arm64 agent와 eBPF object 배포·실행
- `block_rq_insert` / `block_rq_issue` / `block_rq_complete` 이벤트 수집
- block queue, device service, total pipeline latency 분리
- 요청별 File → Syscall → VFS → FS/Page Cache/Writeback → bio → Block → SCSI → UFS transaction graph와 waterfall
- `FileIdentity(device/inode/mount)`와 변경 가능한 path snapshot 분리, block request별 다중 origin 및 Exact/Probable/Probable Async confidence
- arm64 `raw_syscalls` read/write 추적과 `/proc/<pid>/fd/<fd>` metadata/path fallback attribution
- 커널 tracepoint `format` 파일을 읽어 필드 offset을 런타임 구성하므로 고정 offset에 의존하지 않음
- X/Y axis와 grouping을 실행 중 바꾸는 pan/zoom 가능한 Explorer scatter plot
- Summary의 logging/busy/idle time, p50/p95/p99, Read/Write × Sequential/Random × Small/Large 집계
- 같은 device/direction stream에서 `previous sector + sectors == current sector`이면 Sequential, 아니면 Random
- `bytes >= 32 KiB`이면 Large, 그 미만은 Small
- 실시간 이벤트 테이블, NDJSON 기록, 오프라인 재분석, event/summary CSV export
- stdout measurement와 stderr diagnostic JSONL 분리, 세션별 회전 로그와 diagnostic bundle export
- stage inclusive/exclusive/critical-path/unaccounted 계산과 cohort 기반 `Why slow?`
- Phone 없이 GUI 파이프라인을 확인하는 deterministic simulator

## 구조

```text
Windows android-ebpf-studio.exe
  ├─ ADB discovery / root preflight / deploy
  ├─ live UI + analysis + NDJSON/CSV
  └─ adb -s <serial> shell
          ↓
Android android-ebpf-agent (root)
  ├─ tracepoint format parser
  ├─ Aya loader + capability report
  └─ ring-buffer → NDJSON stdout
          ↓
Android kernel eBPF
  ├─ block_rq_insert / block_rq_issue / block_rq_complete
  └─ raw_syscalls/sys_enter + sys_exit (지원 장비)
```

## 요구 환경

- Windows 11 x86_64
- Rust 1.98+
- Android Platform Tools (`adb`가 `PATH`에 있어야 함)
- `adb root`가 가능한 userdebug/eng Android arm64 장비
- Android agent 빌드용 Android NDK r27+ (기본 API 35)
- eBPF 빌드용 nightly Rust, `rust-src`, `bpf-linker`

일반 상용 `user` build는 `adb root`와 임의 BPF program load가 제한되므로 full eBPF mode 대상이 아닙니다.

## 빠른 시작

### Release 다운로드(권장)

[GitHub Releases](https://github.com/SeokMinKo/android-ebpf-studio/releases/latest)에서 최신 ZIP을 내려받아 압축을 풉니다. ZIP에는 다음 파일이 들어 있습니다.

- `android-ebpf-studio.exe`: Windows GUI
- `android-ebpf-agent`: Android arm64 collector
- `android-storage-ebpf.o`: Android kernel에 로드할 eBPF object
- `DEVICE_RUNBOOK.md`: 장비 연결 및 실행 절차

다운로드 무결성은 Release에 함께 게시된 `SHA256SUMS.txt`로 확인할 수 있습니다.

### 1. Windows GUI 빌드

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-windows.ps1
```

출력: `target\release\android-ebpf-studio.exe`

### 2. Android agent 빌드

```powershell
$env:ANDROID_NDK_ROOT = "D:\Android\Sdk\ndk\29.0.13113456"
powershell -ExecutionPolicy Bypass -File .\scripts\build-android-agent.ps1
```

출력: `target\aarch64-linux-android\release\android-ebpf-agent`

### 3. eBPF object 빌드(WSL 권장)

```bash
rustup toolchain install nightly --component rust-src
cargo binstall bpf-linker
./scripts/build-ebpf.sh
```

출력: `crates/android-ebpf/target/bpfel-unknown-none/release/android-storage-ebpf`

### 4. 실행

1. Phone에서 USB debugging을 켜고 연결합니다.
2. `adb devices -l`, `adb root`, `adb wait-for-device`가 성공하는지 확인합니다.
3. Windows GUI에서 `Refresh devices` → 장치 선택 → `Preflight`를 실행합니다.
4. Release ZIP의 세 파일을 같은 폴더에 둔 채 `Start eBPF capture`를 누릅니다. agent/object는 자동 탐색되고 session은 `%LOCALAPPDATA%\AndroidEbpfStudio\sessions`, 구조화 로그는 `%LOCALAPPDATA%\AndroidEbpfStudio\logs\<session-id>`에 자동 저장됩니다.
5. 먼저 `Simulator`로 UI와 저장/CSV 경로를 검증할 수도 있습니다.

## 화면 사용법

- **Summary**: 관측된 logging span, 요청 interval 합집합인 busy time, 나머지 idle time과 조합별 집계를 봅니다.
- **Pipeline**: 요청을 선택하고 계층 waterfall, transaction node/edge, file origin, inclusive/exclusive/critical path와 `Why slow?`를 확인합니다.
- **Explorer**: 기존 축에 FS/UFS/critical-path latency를, Group By에 file/origin/confidence를 조합할 수 있습니다.
- **Block events**: 요청별 latency와 연결된 파일 또는 다중 origin 수를 봅니다.
- **File I/O**: syscall 시점의 `FileIdentity`, path snapshot, FD, byte, syscall latency와 confidence를 봅니다.
- **Diagnostics**: component/code/correlation filter, INFO/DEBUG/TRACE capture level, redacted bundle export를 사용합니다.

## 중요한 정확성 규칙

- tracepoint가 `rq` pointer를 제공하면 issue/complete를 정확한 request identity로 연결합니다.
- `rq`가 없으면 device/sector/length/op 기반 correlation key를 사용합니다. 동일 key가 동시에 중복되면 latency를 억지로 연결하지 않고 uncorrelated로 폐기합니다.
- SCSI/UFS/F2FS/ext4 vendor tracepoint는 이름과 layout이 장비마다 다르므로 runtime `format`을 검사해 지원되는 adapter만 attach합니다. 미지원 계층은 0 ms가 아니라 unavailable입니다.
- SCSI command pointer는 충돌·TTL 검사를 통과한 계층 내부 start/done pairing에만 Exact일 수 있습니다. UFS tag는 controller-local이므로 controller identity를 함께 관측하지 못한 adapter에서는 계층 내부 span도 Probable이며, block request edge 역시 직접 전파 ID가 없으면 Probable입니다.
- kernel pointer/tag는 agent 밖으로 내보내기 전에 session별 opaque ID로 변환합니다.
- Pipeline의 중첩 bar는 단순 합산하지 않습니다. 전체 measured coverage는 interval 합집합이고, 관측되지 않은 틈은 Unaccounted입니다.
- 파일 경로는 syscall과 FD의 attribution입니다. buffered writeback, filesystem metadata, GC가 생성한 block I/O를 특정 파일과 exact하게 연결했다고 표시하지 않습니다.
- `block_rq_insert` 또는 `raw_syscalls`가 없는 커널에서는 해당 queue latency 또는 file view가 unavailable이며 0으로 대체하지 않습니다.
- event loss와 malformed record는 footer/health counter로 분리합니다. 값이 없는데 0으로 가장하지 않습니다.

## 검증

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo check -p android-ebpf-studio --features gui
```

장비 실행 절차와 장애 분류는 [docs/DEVICE_RUNBOOK.md](docs/DEVICE_RUNBOOK.md), NDJSON 형식은 [docs/PROTOCOL.md](docs/PROTOCOL.md)를 참고하세요.

## 상태와 제한

Rust core, Windows GUI, Android agent 및 eBPF object의 compile/test 경계는 CI에서 검사합니다. 실제 Android verifier/SELinux/tracepoint 호환성은 대상 Phone에서 `Preflight`와 첫 capture로 확인해야 합니다. 현재 작업 환경에는 Android Phone이 연결되어 있지 않아 실제 장비 수집은 아직 검증되지 않았습니다.

## License

MIT OR Apache-2.0. eBPF program은 커널 호환을 위해 `Dual MIT/GPL` license section을 사용합니다.
