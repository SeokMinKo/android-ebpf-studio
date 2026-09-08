# Android eBPF Storage Studio

Windows에서 실행되는 Rust GUI가 `adb root` 가능한 Android Phone에 eBPF collector를 배포하고, block I/O를 실시간 로깅·분석하는 도구입니다.

## Histogram 표시

LBA Address 등 수치 분포의 막대는 실제 bin 구간 폭을 따릅니다. 큰 절대 주소나 매우 작은 bin에서도 이웃 구간을 덮지 않으며, 모든 값이 같은 분포만 단일 막대의 표시 폭을 사용합니다. Summary의 축 눈금은 표시 범위에 맞춰 소수 자릿수를 조정하여 가까운 주소와 작은 값도 구분합니다.

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
- 대표 분석 프리셋과 고급 X/Y/Group 설정을 제공하는 pan/zoom Explore scatter plot
- Overview의 logging/busy/idle time, p50/p95/p99, 데이터 품질, Read/Write × Sequential/Random × Small/Large 집계
- 같은 device/direction stream에서 `previous sector + sectors == current sector`이면 Sequential, 아니면 Random
- `bytes >= 32 KiB`이면 Large, 그 미만은 Small
- 실시간 이벤트 테이블, NDJSON 기록, 오프라인 재분석, event/summary CSV export
- stdout measurement와 stderr diagnostic JSONL 분리, 세션별 회전 로그와 diagnostic bundle export
- stage inclusive/exclusive/critical-path/unaccounted 계산과 cohort 기반 `Why slow?`
- Phone 없이 GUI 파이프라인을 확인하는 deterministic simulator
- PID/TID/UID/device/op/size live filter와 Basic/Balanced/Deep/RawAll capture mode
- 커널 per-CPU histogram·정확한 count/bytes 집계, slow-I/O detail suppression과 Top Offenders
- Basic → Armed → Deep → Cooldown 자동 전환, bounded flight-recorder segment와 trigger evidence
- Deep 전용 scheduler/FS/UIC context lane과 user/kernel stack fingerprint cohort
- background session load/export/write, incremental Explorer와 Pipeline/RCA cache
- Diagnostics의 bounded UI/query p50·p95·max, budget 초과, host-message backlog와 capture suppression 효율 측정

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
3. Windows GUI에서 `Refresh ADB devices`로 장치를 선택합니다. `Start analysis`를 누르면 지원 여부와 수집 준비를 확인합니다.
4. Release ZIP의 세 파일을 같은 폴더에 둔 채 `Start analysis`를 누릅니다. agent/object는 자동 탐색되고 session은 `%LOCALAPPDATA%\AndroidEbpfStudio\sessions`, 구조화 로그는 `%LOCALAPPDATA%\AndroidEbpfStudio\logs\<session-id>`에 자동 저장됩니다.
5. 폰 없이 저장된 데이터를 확인하려면 `Session → Open session`에서 NDJSON을 엽니다. Simulator는 테스트용이며 물리 기기 검증을 대신하지 않습니다.

## 화면 사용법

- **Overview**: 관측 시간, latency/workload 집계, 가장 느린 최근 요청, file/probe/event 데이터 품질을 봅니다.
- **Investigate**: 요청 목록에서 하나를 선택해 Pipeline waterfall, file origin, critical path, `Why slow?`, block/transaction/raw file evidence를 한곳에서 확인합니다.
- **Explore**: 기본 그래프는 **LBA distribution**입니다. X축은 완료 시각 기준 Time (ms), Y축은 **Address (MB)**이며 `sector × 512 / 1,000,000`을 사용합니다. Latency, Queue, Overall, window activity, connected footprint, request/CPU timeline, scheduler wait 및 Custom 프리셋도 제공합니다.
- **그래프 조작**: Select로 점 또는 영역을 선택하고 Pan으로 이동합니다. **Clear selection**은 진행 중인 선택 계산까지 취소하며 필터와 확대 범위는 유지합니다. 선택이 없으면 Summary는 전체 필터 적용 그래프를 보여 줍니다.
- **Plot settings**: 색상 분류·점 크기·축·범위를 펼쳐 설정합니다. 해당 그래프에 맞는 조작만 표시합니다. 버튼·탭 최소 높이는 28px이며 Light/Dark/High Contrast를 지원합니다.
- **Compare**: 별도 baseline NDJSON을 읽기 전용으로 열어 현재 세션의 I/O, bytes, p50/p95/p99, queue depth, file attribution 변화량을 비교합니다.
- **Diagnostics**: component/code/correlation filter, INFO/DEBUG/TRACE capture level, UI update·Summary·Explorer·Pipeline rebuild latency, message backlog, capture suppression 효율과 redacted bundle export를 사용합니다. 표시되는 UI update 시간은 CPU가 화면을 구성한 시간이며 GPU presentation 시간은 포함하지 않습니다.

`Advanced capture settings`에서 조건과 capture mode를 바꾼 뒤 `Apply live config`를 누르면 새 generation이 agent와 eBPF map에 원자적으로 적용됩니다. Summary의 kernel aggregate는 전체 관측 I/O이고, Block/File/Pipeline 표는 Balanced 정책으로 보존된 slow/sample detail입니다. 두 수치를 동일한 모집단으로 오해하지 마세요.

## 중요한 정확성 규칙

- tracepoint가 `rq` pointer를 제공하면 issue/complete를 정확한 request identity로 연결합니다.
- `rq`가 없으면 device/sector/length/op 기반 correlation key를 사용합니다. 동일 key가 동시에 중복되면 latency를 억지로 연결하지 않고 uncorrelated로 폐기합니다.
- SCSI/UFS/F2FS/ext4 vendor tracepoint는 이름과 layout이 장비마다 다르므로 runtime `format`을 검사해 지원되는 adapter만 attach합니다. 미지원 계층은 0 ms가 아니라 unavailable입니다.
- SCSI command pointer는 충돌·TTL 검사를 통과한 계층 내부 start/done pairing에만 Exact일 수 있습니다. UFS tag는 controller-local이므로 controller identity를 함께 관측하지 못한 adapter에서는 계층 내부 span도 Probable이며, block request edge 역시 직접 전파 ID가 없으면 Probable입니다.
- kernel pointer/tag는 agent 밖으로 내보내기 전에 session별 opaque ID로 변환합니다.
- Pipeline의 중첩 bar는 단순 합산하지 않습니다. 전체 measured coverage는 interval 합집합이고, 관측되지 않은 틈은 Unaccounted입니다.
- Deep/RawAll에서 target BTF와 typed hook attach가 모두 성공하면 `vfs_read/write → submit_bio → blk_mq_bio_to_request`의 직접 object chain을 파일 identity의 `Exact` 근거로 사용합니다. 성공 후에만 발생하는 `tp_btf/block_bio_frontmerge|backmerge`가 merge origin을 추가하며 bounded origin set overflow를 명시합니다.
- `write_cache_pages` 또는 F2FS writeback hook이 attach된 커널은 `address_space.host → inode → bio/request`를 exact file origin으로 기록합니다. 파일의 device I/O identity는 Exact여도 최초 write syscall과의 인과관계는 별도 token이 없으므로 Exact로 승격하지 않습니다.
- 경로 문자열은 identity가 아닙니다. exact origin의 filesystem device/inode와 같은 `FileIo` snapshot이 있을 때만 경로를 결합하며, 없으면 `<inode dev:ino>`를 표시합니다. filesystem metadata, journal, GC를 임의 사용자 파일로 만들지 않습니다.
- BTF field offset은 `/sys/kernel/btf/vmlinux`에서 실행 시 해석합니다. BTF parse 또는 essential fentry/fexit/tp_btf attach가 실패하면 `exact_file_attribution=false`로 기록하고 기존 tracepoint/휴리스틱 수집을 계속합니다.
- `block_rq_insert` 또는 `raw_syscalls`가 없는 커널에서는 해당 queue latency 또는 file view가 unavailable이며 0으로 대체하지 않습니다.
- event loss와 malformed record는 footer/health counter로 분리합니다. 값이 없는데 0으로 가장하지 않습니다.
- Scheduler/GC/writeback/UIC marker와 stack fingerprint는 Deep capture의 원인 후보 문맥입니다. 직접 correlation edge가 없으면 `ContextOnly`이며 additive latency 또는 확정 원인으로 표시하지 않습니다.
- histogram percentile은 bucket 범위 기반 근사치입니다. UI에 approximate로 표시하고 offline exact summary와 구분합니다.

## 검증

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo check -p android-ebpf-studio --features gui
```

장비 실행 절차와 장애 분류는 [docs/DEVICE_RUNBOOK.md](docs/DEVICE_RUNBOOK.md), NDJSON 형식은 [docs/PROTOCOL.md](docs/PROTOCOL.md)를 참고하세요. 다른 환경에서 exact file attribution 작업을 이어갈 때는 [docs/EXACT_FILE_ATTRIBUTION_HANDOFF.md](docs/EXACT_FILE_ATTRIBUTION_HANDOFF.md)를 시작점으로 사용하세요.

공통 필터의 실제 입력과 적용·빈 결과 화면 캡처 절차는 [Common filter native QA](docs/COMMON_FILTER_QA.md)를 참고하세요.

## 상태와 제한

Host 테스트, native renderer, 실제 설치 EXE, 물리 기기 결과는 별도 검증 범위입니다. 저장된 root 세션으로 Read FilePath와 렌더링 좌표를 대조했지만, 모든 기기에서 Exact 경로가 보장되거나 전체 그래프 매트릭스가 통과했다는 의미는 아닙니다. 2026-09-08에 root V2606A를 다시 연결하여 서로 다른 두 파일의 248회 O_DIRECT Read를 수집했습니다. 호출별 경로·PID·시간·크기는 모두 raw syscall 증거와 일치했고, 대응하는 249개 block Read의 bytes와 inode도 ground truth와 일치했습니다(한 호출은 두 block 요청으로 분할). 이 세션의 경로 분류는 Probable이며 Exact 검증 통과로 해석하지 않습니다. 전체 visible graph 상호작용 매트릭스는 계속 검증 중입니다. Compare LBA는 저장된 두 물리 세션으로 All/Read/Write·시간·PID·process·device·file·빈 결과·복합 필터를 3개 테마에서 실행했고, 30개 설치 EXE 실행의 60개 pane에서 요청 key·Read/Write bytes·시간/MB 좌표가 독립 기준값과 일치했습니다. 이 수치 검증은 모든 화면의 시각 품질이나 전체 그래프 acceptance 통과를 뜻하지 않습니다. 재현용 필터/export QA 범위는 [Compare filter QA](docs/COMPARE_FILTER_QA.md)에 설명합니다.

- Exact FilePath는 실제 경로와 인과 증거가 함께 있어야 합니다. inode만 있거나 시간상 가까운 경로 후보만 있는 요청을 Exact 경로로 승격하지 않습니다. Perfetto만으로 FilePath 검증을 통과 처리하지 않습니다.
- 이후 pathless 관측이 앞서 기록된 경로를 덮지 않으며, 시간 기반 경로 추정은 Probable로 제한합니다. 서로 다른 후보는 미해결로 남길 수 있습니다.
- Pipeline은 관측된 Read/Write 방향을 유지하고, waterfall은 음수 시작 offset을 포함한 전체 구간을 그립니다. Critical path는 겹치는 후손 구간을 중복 합산하지 않습니다.
- eBPF recursion misses는 ring loss와 별도인 probe 호출 손실 지표입니다. 기존 물리 수집에서 completion 누락과 일부 Unresolved가 남았으므로 전체 acceptance는 미완료입니다.
- Explorer downsampling은 실제 측정값의 extrema·endpoint·sparse gap 보존을 검증합니다. queue_depth_at_issue와 queue_depth_after는 서로 다른 관측치이며 하드웨어 queue depth로 해석하지 않습니다.

자세한 근거와 범위는 [Acceptance status](docs/ACCEPTANCE_STATUS.md), [FilePath coverage](docs/FILEPATH_COVERAGE.md), [UI refinement](docs/UI_REFINEMENT.md), [Critical path](docs/CRITICAL_PATH_INTERVALS.md), [LBA defaults](LBA_DEFAULT.md), [Sampling](SHAPE_SAMPLING.md)를 참고하세요. Git main, 공개 Release ZIP, 로컬 설치 EXE는 자동으로 동일 버전이 되지 않습니다. 설치본의 BUILD-MANIFEST.json에서 source_commit과 각 구성요소 해시를 확인하세요.

## License

MIT OR Apache-2.0. eBPF program은 커널 호환을 위해 `Dual MIT/GPL` license section을 사용합니다.
