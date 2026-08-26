# Android eBPF Storage Studio

Windows에서 실행되는 Rust GUI가 `adb root` 가능한 Android Phone에 eBPF collector를 배포하고, block I/O를 실시간 로깅·분석하는 도구입니다.

## 현재 MVP 기능

- ADB 장치 검색과 serial 고정
- `adb root`, ABI, Android/kernel 버전, BTF, tracefs, block/UFS event preflight
- Android arm64 agent와 eBPF object 배포·실행
- `block_rq_issue` / `block_rq_complete` 이벤트 수집
- 커널 tracepoint `format` 파일을 읽어 필드 offset을 런타임 구성하므로 고정 offset에 의존하지 않음
- IOPS, MiB/s, queue depth, p50/p95/p99 latency, read/write bytes
- sector 연속성과 시간 window 기반 sequential/random 분류
- 실시간 이벤트 테이블, NDJSON 기록, 오프라인 재분석, event/summary CSV export
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
  └─ block_rq_issue / block_rq_complete
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
4. `Deploy + Start eBPF`를 누르고 Android agent, eBPF object, session 저장 경로를 차례로 선택합니다.
5. 먼저 `Simulator`로 UI와 저장/CSV 경로를 검증할 수도 있습니다.

## 중요한 정확성 규칙

- tracepoint가 `rq` pointer를 제공하면 issue/complete를 정확한 request identity로 연결합니다.
- `rq`가 없으면 device/sector/length/op 기반 correlation key를 사용합니다. 동일 key가 동시에 중복되면 latency를 억지로 연결하지 않고 uncorrelated로 폐기합니다.
- UFS/vendor tracepoint는 이름과 layout이 장비마다 다르므로 자동 탐지만 하며, 현재 MVP의 필수 수집축은 generic block layer입니다.
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
