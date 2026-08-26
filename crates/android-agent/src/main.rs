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

use android_ebpf_agent::trace_format::{parse_layout, validate_pair};
use android_ebpf_protocol::{
    BlockComplete, BlockIssue, IoOperation, ProbeCapabilities, SCHEMA_VERSION, StorageEvent,
    WireRecord, write_record,
};
use android_ebpf_types::{
    KIND_BLOCK_COMPLETE, KIND_BLOCK_ISSUE, KernelEvent, OP_DISCARD, OP_FLUSH, OP_READ, OP_WRITE,
    TraceLayout,
};
use anyhow::{Context, Result, bail};
use aya::{Ebpf, Pod, maps::Array, maps::RingBuf, programs::TracePoint};
use clap::{Parser, Subcommand};

const ISSUE_FORMAT: &str = "/sys/kernel/tracing/events/block/block_rq_issue/format";
const COMPLETE_FORMAT: &str = "/sys/kernel/tracing/events/block/block_rq_complete/format";

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
    let (capabilities, _, _) = capabilities()?;
    let mut output = BufWriter::new(std::io::stdout().lock());
    write_record(
        &mut output,
        &WireRecord::Capabilities {
            schema_version: SCHEMA_VERSION,
            capabilities,
        },
    )?;
    output.flush()?;
    Ok(())
}

fn capture(object: &Path, health_interval_ms: u64) -> Result<()> {
    if health_interval_ms == 0 {
        bail!("health interval must be positive")
    }
    let (capabilities, issue_layout, complete_layout) = capabilities()?;
    if !capabilities.block_issue || !capabilities.block_complete {
        bail!("mandatory block tracepoints are not available")
    }
    let mut bpf = Ebpf::load_file(object)
        .with_context(|| format!("failed to load eBPF object {}", object.display()))?;
    configure_layout(&mut bpf, "ISSUE_LAYOUT", issue_layout)?;
    configure_layout(&mut bpf, "COMPLETE_LAYOUT", complete_layout)?;
    attach(&mut bpf, "block_rq_issue", "block_rq_issue")?;
    attach(&mut bpf, "block_rq_complete", "block_rq_complete")?;
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
            capabilities,
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

fn capabilities() -> Result<(ProbeCapabilities, TraceLayout, TraceLayout)> {
    let issue_text =
        fs::read_to_string(ISSUE_FORMAT).with_context(|| format!("cannot read {ISSUE_FORMAT}"))?;
    let complete_text = fs::read_to_string(COMPLETE_FORMAT)
        .with_context(|| format!("cannot read {COMPLETE_FORMAT}"))?;
    let issue = parse_layout(&issue_text)?;
    let complete = parse_layout(&complete_text)?;
    let exact = validate_pair(&issue, &complete)?;
    let ufs_events = discover_events("ufs");
    Ok((
        ProbeCapabilities {
            bpf_syscall: true,
            btf: Path::new("/sys/kernel/btf/vmlinux").is_file(),
            ring_buffer: true,
            block_issue: true,
            block_complete: true,
            exact_request_correlation: exact,
            ufs_events,
            fs_events: discover_events("f2fs"),
        },
        issue,
        complete,
    ))
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

fn attach(bpf: &mut Ebpf, program_name: &str, event_name: &str) -> Result<()> {
    let program: &mut TracePoint = bpf
        .program_mut(program_name)
        .with_context(|| format!("{program_name} program is missing"))?
        .try_into()?;
    program.load()?;
    program.attach("block", event_name)?;
    Ok(())
}

fn parse_kernel_event(bytes: &[u8]) -> Option<StorageEvent> {
    if bytes.len() < std::mem::size_of::<KernelEvent>() {
        return None;
    }
    let event = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<KernelEvent>()) };
    let (device_major, device_minor) = decode_device(event.device);
    match event.kind {
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
        _ => None,
    }
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
