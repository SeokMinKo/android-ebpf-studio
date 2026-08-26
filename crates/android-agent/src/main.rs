use std::{
    fs,
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use android_ebpf_agent::trace_format::{parse_layout, parse_raw_syscall_layout, validate_pair};
use android_ebpf_protocol::{
    AttributionConfidence, BlockComplete, BlockInsert, BlockIssue, FileIo, IoOperation,
    ProbeCapabilities, SCHEMA_VERSION, StorageEvent, WireRecord, write_record,
};
use android_ebpf_types::{
    KIND_BLOCK_COMPLETE, KIND_BLOCK_INSERT, KIND_BLOCK_ISSUE, KIND_FILE_IO, KernelEvent,
    OP_DISCARD, OP_FLUSH, OP_READ, OP_WRITE, RawSyscallLayout, TraceLayout,
};
use anyhow::{Context, Result, bail};
use aya::{Ebpf, Pod, maps::Array, maps::RingBuf, programs::TracePoint};
use clap::{Parser, Subcommand};

const ISSUE_FORMAT: &str = "/sys/kernel/tracing/events/block/block_rq_issue/format";
const COMPLETE_FORMAT: &str = "/sys/kernel/tracing/events/block/block_rq_complete/format";
const INSERT_FORMAT: &str = "/sys/kernel/tracing/events/block/block_rq_insert/format";
const SYS_ENTER_FORMAT: &str = "/sys/kernel/tracing/events/raw_syscalls/sys_enter/format";
const SYS_EXIT_FORMAT: &str = "/sys/kernel/tracing/events/raw_syscalls/sys_exit/format";

#[derive(Debug, Parser)]
#[command(version, about = "Android storage eBPF collector")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Probe,
    Capture {
        #[arg(long)]
        bpf_object: PathBuf,
        #[arg(long, default_value_t = 1000)]
        health_interval_ms: u64,
    },
}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct LayoutValue(TraceLayout);

unsafe impl Pod for LayoutValue {}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct RawSyscallLayoutValue(RawSyscallLayout);

unsafe impl Pod for RawSyscallLayoutValue {}

struct CollectorConfig {
    capabilities: ProbeCapabilities,
    issue: TraceLayout,
    complete: TraceLayout,
    insert: Option<TraceLayout>,
    syscall: Option<RawSyscallLayout>,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Probe => emit_probe(),
        Command::Capture {
            bpf_object,
            health_interval_ms,
        } => capture(&bpf_object, health_interval_ms),
    }
}

fn emit_probe() -> Result<()> {
    let config = capabilities()?;
    let mut output = BufWriter::new(std::io::stdout().lock());
    write_record(
        &mut output,
        &WireRecord::Capabilities {
            schema_version: SCHEMA_VERSION,
            capabilities: config.capabilities,
        },
    )?;
    output.flush()?;
    Ok(())
}

fn capture(object: &Path, health_interval_ms: u64) -> Result<()> {
    if health_interval_ms == 0 {
        bail!("health interval must be positive")
    }
    let config = capabilities()?;
    if !config.capabilities.block_issue || !config.capabilities.block_complete {
        bail!("mandatory block tracepoints are not available")
    }
    let mut bpf = Ebpf::load_file(object)
        .with_context(|| format!("failed to load eBPF object {}", object.display()))?;
    configure_layout(&mut bpf, "ISSUE_LAYOUT", config.issue)?;
    configure_layout(&mut bpf, "COMPLETE_LAYOUT", config.complete)?;
    attach(&mut bpf, "block_rq_issue", "block", "block_rq_issue")?;
    attach(&mut bpf, "block_rq_complete", "block", "block_rq_complete")?;
    if let Some(layout) = config.insert {
        configure_layout(&mut bpf, "INSERT_LAYOUT", layout)?;
        attach(&mut bpf, "block_rq_insert", "block", "block_rq_insert")?;
    }
    if let Some(layout) = config.syscall {
        configure_syscall_layout(&mut bpf, layout)?;
        attach(&mut bpf, "raw_sys_enter", "raw_syscalls", "sys_enter")?;
        attach(&mut bpf, "raw_sys_exit", "raw_syscalls", "sys_exit")?;
    }
    let map = bpf.take_map("EVENTS").context("EVENTS map is missing")?;
    let mut ring = RingBuf::try_from(map)?;

    let running = Arc::new(AtomicBool::new(true));
    let signal = running.clone();
    ctrlc::set_handler(move || signal.store(false, Ordering::Release))?;

    let mut output = BufWriter::new(std::io::stdout().lock());
    write_record(
        &mut output,
        &WireRecord::Hello {
            schema_version: SCHEMA_VERSION,
            agent_version: env!("CARGO_PKG_VERSION").into(),
            boot_id: read_trimmed("/proc/sys/kernel/random/boot_id").unwrap_or_default(),
            kernel_release: read_trimmed("/proc/sys/kernel/osrelease").unwrap_or_default(),
        },
    )?;
    write_record(
        &mut output,
        &WireRecord::Capabilities {
            schema_version: SCHEMA_VERSION,
            capabilities: config.capabilities,
        },
    )?;
    output.flush()?;

    let health_interval = Duration::from_millis(health_interval_ms);
    let mut last_health = Instant::now();
    let mut sequence = 0_u64;
    let mut emitted = 0_u64;
    let mut rejected = 0_u64;
    while running.load(Ordering::Acquire) {
        let mut had_event = false;
        while let Some(item) = ring.next() {
            had_event = true;
            match parse_kernel_event(&item) {
                Some(event) => {
                    sequence += 1;
                    write_record(
                        &mut output,
                        &WireRecord::Event {
                            schema_version: SCHEMA_VERSION,
                            sequence,
                            event,
                        },
                    )?;
                    emitted += 1;
                }
                None => rejected += 1,
            }
        }
        if last_health.elapsed() >= health_interval {
            write_record(
                &mut output,
                &WireRecord::Health {
                    schema_version: SCHEMA_VERSION,
                    emitted_events: emitted,
                    kernel_drops: 0,
                    userspace_drops: rejected,
                },
            )?;
            output.flush()?;
            last_health = Instant::now();
        }
        if !had_event {
            thread::sleep(Duration::from_millis(2));
        }
    }
    write_record(
        &mut output,
        &WireRecord::Footer {
            schema_version: SCHEMA_VERSION,
            events_seen: emitted + rejected,
            events_persisted: emitted,
            events_dropped: 0,
            events_rejected: rejected,
        },
    )?;
    output.flush()?;
    Ok(())
}

fn capabilities() -> Result<CollectorConfig> {
    let issue_text =
        fs::read_to_string(ISSUE_FORMAT).with_context(|| format!("cannot read {ISSUE_FORMAT}"))?;
    let complete_text = fs::read_to_string(COMPLETE_FORMAT)
        .with_context(|| format!("cannot read {COMPLETE_FORMAT}"))?;
    let issue = parse_layout(&issue_text)?;
    let complete = parse_layout(&complete_text)?;
    let exact = validate_pair(&issue, &complete)?;
    let insert = fs::read_to_string(INSERT_FORMAT)
        .ok()
        .and_then(|text| parse_layout(&text).ok());
    let syscall = fs::read_to_string(SYS_ENTER_FORMAT)
        .ok()
        .zip(fs::read_to_string(SYS_EXIT_FORMAT).ok())
        .and_then(|(enter, exit)| parse_raw_syscall_layout(&enter, &exit).ok());
    let ufs_events = discover_events("ufs");
    Ok(CollectorConfig {
        capabilities: ProbeCapabilities {
            bpf_syscall: true,
            btf: Path::new("/sys/kernel/btf/vmlinux").is_file(),
            ring_buffer: true,
            block_insert: insert.is_some(),
            block_issue: true,
            block_complete: true,
            file_io: syscall.is_some(),
            exact_request_correlation: exact,
            ufs_events,
            fs_events: discover_events("f2fs"),
        },
        issue,
        complete,
        insert,
        syscall,
    })
}

fn discover_events(needle: &str) -> Vec<String> {
    let Ok(groups) = fs::read_dir("/sys/kernel/tracing/events") else {
        return Vec::new();
    };
    let mut result = Vec::new();
    for group in groups.flatten() {
        let name = group.file_name().to_string_lossy().into_owned();
        if !name.to_ascii_lowercase().contains(needle) {
            continue;
        }
        if let Ok(events) = fs::read_dir(group.path()) {
            result.extend(events.flatten().take(128).filter_map(|event| {
                event
                    .path()
                    .join("format")
                    .is_file()
                    .then(|| format!("{name}/{}", event.file_name().to_string_lossy()))
            }));
        }
    }
    result.sort();
    result
}

fn configure_layout(bpf: &mut Ebpf, name: &str, layout: TraceLayout) -> Result<()> {
    let map = bpf
        .map_mut(name)
        .with_context(|| format!("{name} map is missing"))?;
    let mut array = Array::<_, LayoutValue>::try_from(map)?;
    array.set(0, LayoutValue(layout), 0)?;
    Ok(())
}

fn configure_syscall_layout(bpf: &mut Ebpf, layout: RawSyscallLayout) -> Result<()> {
    let map = bpf
        .map_mut("RAW_SYSCALL_LAYOUT")
        .context("RAW_SYSCALL_LAYOUT map is missing")?;
    let mut array = Array::<_, RawSyscallLayoutValue>::try_from(map)?;
    array.set(0, RawSyscallLayoutValue(layout), 0)?;
    Ok(())
}

fn attach(bpf: &mut Ebpf, program_name: &str, group: &str, event_name: &str) -> Result<()> {
    let program: &mut TracePoint = bpf
        .program_mut(program_name)
        .with_context(|| format!("{program_name} program is missing"))?
        .try_into()?;
    program.load()?;
    program.attach(group, event_name)?;
    Ok(())
}

fn parse_kernel_event(bytes: &[u8]) -> Option<StorageEvent> {
    if bytes.len() < std::mem::size_of::<KernelEvent>() {
        return None;
    }
    let event = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<KernelEvent>()) };
    let (device_major, device_minor) = decode_device(event.device);
    match event.kind {
        KIND_BLOCK_INSERT => Some(StorageEvent::BlockInsert(BlockInsert {
            ts_ns: event.ts_ns,
            request_id: event.request_id,
            device_major,
            device_minor,
            sector: event.sector,
            sectors: event.sectors,
            bytes: event.bytes,
            operation: decode_operation(event.operation),
        })),
        KIND_BLOCK_ISSUE => Some(StorageEvent::BlockIssue(BlockIssue {
            ts_ns: event.ts_ns,
            request_id: event.request_id,
            device_major,
            device_minor,
            sector: event.sector,
            sectors: event.sectors,
            bytes: event.bytes,
            operation: decode_operation(event.operation),
            pid: event.pid,
            tid: event.tid,
            cpu: event.cpu,
            comm: decode_comm(&event.comm),
        })),
        KIND_BLOCK_COMPLETE => Some(StorageEvent::BlockComplete(BlockComplete {
            ts_ns: event.ts_ns,
            request_id: event.request_id,
            device_major,
            device_minor,
            status: event.status,
        })),
        KIND_FILE_IO => {
            let path = resolve_fd_path(event.pid, event.fd);
            let confidence = if path.is_some() {
                AttributionConfidence::Attributed
            } else {
                AttributionConfidence::Unknown
            };
            Some(StorageEvent::FileIo(FileIo {
                start_ts_ns: event.start_ts_ns,
                end_ts_ns: event.ts_ns,
                operation: decode_operation(event.operation),
                fd: event.fd,
                requested_bytes: event.requested_bytes,
                completed_bytes: event.return_value,
                pid: event.pid,
                tid: event.tid,
                comm: decode_comm(&event.comm),
                path,
                confidence,
            }))
        }
        _ => None,
    }
}

fn resolve_fd_path(pid: u32, fd: i32) -> Option<String> {
    if fd < 0 {
        return None;
    }
    let path = fs::read_link(format!("/proc/{pid}/fd/{fd}")).ok()?;
    let mut value = path.to_string_lossy().into_owned();
    if value.len() > 4096 {
        value.truncate(value.floor_char_boundary(4096));
    }
    Some(value)
}

fn decode_device(device: u32) -> (u32, u32) {
    let major = (device >> 8) & 0x0fff;
    let minor = (device & 0x00ff) | ((device >> 12) & 0x0fff00);
    (major, minor)
}

fn decode_operation(value: u8) -> IoOperation {
    match value {
        OP_READ => IoOperation::Read,
        OP_WRITE => IoOperation::Write,
        OP_FLUSH => IoOperation::Flush,
        OP_DISCARD => IoOperation::Discard,
        _ => IoOperation::Other,
    }
}

fn decode_comm(value: &[u8; 16]) -> String {
    let length = value
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(value.len());
    String::from_utf8_lossy(&value[..length]).into_owned()
}

fn read_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().into())
}
