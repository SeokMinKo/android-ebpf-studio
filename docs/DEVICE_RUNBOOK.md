# Device Runbook

## Preflight

```powershell
adb devices -l
adb -s SERIAL root
adb -s SERIAL wait-for-device
adb -s SERIAL shell id
adb -s SERIAL shell getprop ro.product.cpu.abi
adb -s SERIAL shell uname -r
adb -s SERIAL shell test -r /sys/kernel/tracing/events/block/block_rq_issue/format
adb -s SERIAL shell test -r /sys/kernel/tracing/events/block/block_rq_complete/format
adb -s SERIAL shell test -r /sys/kernel/tracing/events/block/block_rq_insert/format
adb -s SERIAL shell test -r /sys/kernel/tracing/events/raw_syscalls/sys_enter/format
adb -s SERIAL shell test -r /sys/kernel/tracing/events/raw_syscalls/sys_exit/format
adb -s SERIAL shell test -r /sys/kernel/btf/vmlinux
```

필수 조건은 root shell, arm64 ABI, issue/complete block tracepoint입니다. insert가 없으면 queue latency가, raw_syscalls가 없으면 file attribution이 비활성화됩니다. BTF와 UFS event는 capability로 기록하지만 generic block capture의 필수 조건은 아닙니다.

## GUI 자동 경로

Release ZIP을 한 폴더에 그대로 풀면 GUI가 실행 파일 옆의 `android-ebpf-agent`와 `android-storage-ebpf.o`를 자동으로 찾습니다. 캡처 출력은 기본적으로 다음 위치에 생성됩니다.

```text
%LOCALAPPDATA%\AndroidEbpfStudio\sessions\android-storage-<unix-time>.ndjson
```

파일이 빠졌다면 임의 파일 선택 창을 띄우지 않고 어떤 bundle 파일이 누락됐는지 Diagnostics에 표시합니다.

## Collector 수동 실행

```powershell
adb -s SERIAL shell mkdir -p /data/local/tmp/android-ebpf-studio
adb -s SERIAL push android-ebpf-agent /data/local/tmp/android-ebpf-studio/agent
adb -s SERIAL push android-storage-ebpf /data/local/tmp/android-ebpf-studio/storage-ebpf.o
adb -s SERIAL shell chmod 0755 /data/local/tmp/android-ebpf-studio/agent
adb -s SERIAL shell /data/local/tmp/android-ebpf-studio/agent probe
adb -s SERIAL shell /data/local/tmp/android-ebpf-studio/agent capture --bpf-object /data/local/tmp/android-ebpf-studio/storage-ebpf.o
```

stdout은 NDJSON protocol 전용입니다. verifier 또는 attach 오류는 stderr로 확인합니다.

## Failure guide

| 증상 | 확인 | 의미/조치 |
| --- | --- | --- |
| `adbd cannot run as root in production builds` | `getprop ro.build.type` | user build입니다. userdebug/eng image가 필요합니다. |
| `Operation not permitted` at BPF load | `dmesg`, SELinux audit | capability/SELinux/kernel config가 load를 거부했습니다. 정책을 자동 변경하지 말고 diagnostic을 보존합니다. |
| missing block format | `/sys/kernel/tracing/events/block` | kernel config/vendor trace event 차이입니다. full mode를 중단합니다. |
| verifier rejection | agent stderr, `dmesg` | layout, helper, map 또는 kernel BPF feature 불일치입니다. object/profile을 수정합니다. |
| high userspace/kernel drops | `health` records | probe 축소, ring buffer 확대 또는 host 처리율 개선 후 새 session을 시작합니다. |
| p95/p99가 비정상적으로 0 | footer/rejected/uncorrelated | 실제 0으로 간주하지 말고 correlation과 record rejection을 확인합니다. |
| Queue latency가 모두 없음 | `block_rq_insert/format`, capability | 커널이 insert tracepoint를 노출하지 않거나 attach가 실패했습니다. |
| File I/O가 없음 | `raw_syscalls/*/format`, capability | syscall tracepoint가 없거나 해당 수집 동안 read/write가 관측되지 않았습니다. |
| SCSI/UFS/FS bar가 없음 | Pipeline capability와 tracepoint inventory | 0 ms가 아니라 해당 커널에서 아직 측정되지 않은 계층입니다. Simulator로 UI 전체 동작을 별도 확인할 수 있습니다. |

## Cleanup

수집 프로세스를 중지한 뒤 다음 staging directory만 제거합니다.

```powershell
adb -s SERIAL shell rm -rf /data/local/tmp/android-ebpf-studio
```

시스템 BPF pin, SELinux policy, kernel image는 이 도구가 수정하지 않습니다.
