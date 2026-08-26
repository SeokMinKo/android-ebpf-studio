# Research memo — Deep I/O Attribution & Pipeline

- Artifact: `research@1`
- Status: `VERIFIED`
- Current: `true`
- Derived from: user request, repository baseline `10b2d8f`, external sources checked 2026-08-26

## RQ-001 — 동적 probe 선택

**결정:** static tracepoint를 우선하고, BTF가 있을 때 fentry/fexit 또는 fprobe를 사용하며, 마지막 fallback으로 kprobe/kretprobe를 사용한다. runtime capability와 attach 결과가 최종 권위다.

**근거:** Linux fprobe event는 함수 entry/exit를 지원하고 BTF가 있으면 이름 기반 function argument를 가져올 수 있다. Android vendor kernel은 config/BTF/function 노출이 다르므로 지원을 가정할 수 없다. [Fprobe-based Event Tracing](https://docs.kernel.org/trace/fprobetrace.html), [BPF Type Format](https://docs.kernel.org/bpf/btf.html)

**대안:** vendor별 고정 offset은 초기 구현이 단순하지만 kernel update 시 잘못된 값을 조용히 읽을 위험이 있어 기각한다.

**영향:** REQ-001~004, DEC-007.

## RQ-002 — bio/request 그래프 필요성

**결정:** file→device 관계는 평면 request가 아니라 DAG로 모델링한다.

**근거:** Linux block tracepoint API에는 bio completion, request allocation/issue/complete뿐 아니라 bio front/back merge, split, remap이 별도 사건으로 정의되어 있다. 따라서 한 file operation과 한 request의 1:1 가정은 성립하지 않는다. [The Linux Kernel Tracepoint API](https://docs.kernel.org/core-api/tracepoint.html)

**영향:** REQ-020~024, INV-002/003, DEC-001.

## RQ-003 — buffered I/O attribution 한계

**결정:** file identity가 writeback/bio에 직접 보존된 경우 device I/O의 파일은 연결할 수 있지만 최초 write syscall과 background writeback의 관계는 별도 causation token 없이는 Exact로 표시하지 않는다.

**근거:** Linux buffered I/O는 page cache를 사용하고 dirty cache가 나중에 writeback된다. syscall 종료와 device write가 같은 실행 문맥이나 시점에 있지 않을 수 있다. [Supported File Operations — Buffered I/O](https://docs.kernel.org/filesystems/iomap/operations.html), [Overview of the Linux Virtual File System](https://docs.kernel.org/filesystems/vfs.html)

**영향:** REQ-025/026/036, SCN-003/004.

## RQ-004 — UFS command pairing

**결정:** target에 `ufshcd_command`가 존재하고 필드가 호환될 때 device/controller와 tag lifetime을 이용해 SEND/COMPLETE를 pair한다.

**근거:** Android common kernel의 UFS trace event는 device name, state string, tag, transfer length, LBA와 opcode를 제공한다. Vendor kernel의 실제 format은 capture 전에 다시 검사해야 한다. [Android common UFS trace events](https://android.googlesource.com/kernel/common/+/bce1305c0ece3/include/trace/events/ufs.h)

**영향:** REQ-031, INV-006.

## RQ-005 — 현재 repository 진단 gap

**관찰:** `crates/android-agent/src/main.rs`는 health의 `kernel_drops`와 footer `events_dropped`를 항상 0으로 기록한다. `crates/desktop/src/capture.rs`의 stderr reader는 16 KiB buffer를 한 번 읽고 종료한다. 현재 desktop tracing subscriber는 console formatter만 초기화한다.

**결정:** agent stderr continuous JSONL drain, host rotating file sink, actual reserve/drop counters와 session integrity event가 필요하다.

**영향:** REQ-060~069, NFR-002~007, DEC-006.

## 불확실성

- 목표 단말의 tracepoint format/BTF/kallsyms가 제공되지 않아 SCSI↔UFS와 F2FS/ext4의 구체 hook 목록은 확정 불가다.
- `bpf_d_path` 등 helper 사용 가능성은 program type과 vendor kernel에 의존하므로 path 획득의 필수 경로로 두지 않는다.
- 성능 overhead와 UI frame-time threshold는 실제 workload baseline 전에는 수치 확정이 불가능하다.
