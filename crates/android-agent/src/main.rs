use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    fs,
    io::{BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use android_ebpf_agent::trace_format::{
    parse_layout, parse_pipeline_layout, parse_raw_syscall_layout, validate_pair,
};
use android_ebpf_protocol::{
    AdaptiveController, AggregateCounters, AggregateSnapshot, AttributionConfidence, BlockComplete,
    BlockInsert, BlockIssue, CapabilityState, CaptureConfig, CaptureControlAck,
    CaptureControlCommand, CaptureFilter, CaptureMode, CaptureState, ControlOutcome,
    CorrelationConfidence, DetailPolicy, DiagnosticLevel, DiagnosticRecord, EdgeConfidence, FileIo,
    HeavyHitterDimension, HeavyHitterEntry, HeavyHitterMetric, HeavyHitterSnapshot, Histogram,
    HistogramMetric, IoOperation, PipelineLayer, PipelineObservation, PipelinePhase,
    ProbeCapabilities, ProbePlan, SCHEMA_VERSION, SegmentRecord, StackFingerprintRecord, StackKind,
    StorageEvent, WireRecord, write_record,
};
use android_ebpf_types::{
    FilterKey, HISTOGRAM_BUCKETS, KIND_BLOCK_COMPLETE, KIND_BLOCK_INSERT, KIND_BLOCK_ISSUE,
    KIND_FILE_IO, KIND_PIPELINE, KernelAggregate, KernelEvent, LAYER_FILESYSTEM, LAYER_SCHEDULER,
    LAYER_SCSI, LAYER_UFS, MODE_BALANCED, MODE_BASIC, MODE_DEEP, MODE_RAW_ALL, OP_DISCARD,
    OP_FLUSH, OP_OTHER, OP_READ, OP_WRITE, PHASE_BEGIN, PHASE_END, PHASE_INSTANT,
    PipelineTraceLayout, RawFilterConfig, RawSyscallLayout, STACK_ID_UNAVAILABLE, TraceLayout,
};
use anyhow::{Context, Result, bail};
use aya::{
    Ebpf, Pod,
    maps::{Array, HashMap as UserHashMap, MapData, PerCpuArray, RingBuf, StackTraceMap},
    programs::TracePoint,
};
use clap::{Parser, Subcommand, ValueEnum};

const ISSUE_FORMAT: &str = "/sys/kernel/tracing/events/block/block_rq_issue/format";
const COMPLETE_FORMAT: &str = "/sys/kernel/tracing/events/block/block_rq_complete/format";
const INSERT_FORMAT: &str = "/sys/kernel/tracing/events/block/block_rq_insert/format";
const SYS_ENTER_FORMAT: &str = "/sys/kernel/tracing/events/raw_syscalls/sys_enter/format";
const SYS_EXIT_FORMAT: &str = "/sys/kernel/tracing/events/raw_syscalls/sys_exit/format";
static LOG_LEVEL: AtomicU8 = AtomicU8::new(2);

#[derive(Debug, Clone, Copy, ValueEnum)]
enum LogLevelArg {
    Info,
    Debug,
    Trace,
}

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
        #[arg(long, default_value = "unknown")]
        session_id: String,
        #[arg(long, value_enum, default_value_t = LogLevelArg::Info)]
        log_level: LogLevelArg,
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

#[repr(transparent)]
#[derive(Clone, Copy)]
struct PipelineTraceLayoutValue(PipelineTraceLayout);

unsafe impl Pod for PipelineTraceLayoutValue {}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct RawFilterConfigValue(RawFilterConfig);

unsafe impl Pod for RawFilterConfigValue {}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct FilterKeyValue(FilterKey);

unsafe impl Pod for FilterKeyValue {}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct KernelAggregateValue(KernelAggregate);

unsafe impl Pod for KernelAggregateValue {}

struct FilterMaps {
    active: Array<MapData, u64>,
    configs: UserHashMap<MapData, u64, RawFilterConfigValue>,
    pids: UserHashMap<MapData, FilterKeyValue, u8>,
    tids: UserHashMap<MapData, FilterKeyValue, u8>,
    uids: UserHashMap<MapData, FilterKeyValue, u8>,
    devices: UserHashMap<MapData, FilterKeyValue, u8>,
    operations: UserHashMap<MapData, FilterKeyValue, u8>,
}

struct PipelineProbe {
    program_name: &'static str,
    map_name: &'static str,
    group: String,
    event_name: String,
    layer: PipelineLayer,
    layout: PipelineTraceLayout,
    format_hash: String,
}

struct ContextProbe {
    program_name: &'static str,
    group: String,
    event_name: String,
    layer: PipelineLayer,
    format_hash: String,
}

struct CollectorConfig {
    capabilities: ProbeCapabilities,
    issue: TraceLayout,
    complete: TraceLayout,
    insert: Option<TraceLayout>,
    syscall: Option<RawSyscallLayout>,
    pipeline_probes: Vec<PipelineProbe>,
    context_probes: Vec<ContextProbe>,
}

#[derive(Debug, Default)]
struct TopEntry {
    count: u64,
    bytes: u64,
    cumulative_latency_ns: u64,
    max_latency_ns: u64,
    confidence: Option<EdgeConfidence>,
}

#[derive(Debug)]
struct BoundedTop {
    capacity: usize,
    entries: HashMap<String, TopEntry>,
    evicted_keys: u64,
    total_metric: u64,
}

impl BoundedTop {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: HashMap::new(),
            evicted_keys: 0,
            total_metric: 0,
        }
    }

    fn observe(
        &mut self,
        key: String,
        bytes: u64,
        latency_ns: u64,
        confidence: Option<EdgeConfidence>,
    ) {
        self.total_metric = self.total_metric.saturating_add(latency_ns);
        if !self.entries.contains_key(&key) && self.entries.len() == self.capacity {
            let candidate = self
                .entries
                .iter()
                .min_by_key(|(_, value)| value.cumulative_latency_ns)
                .map(|(key, value)| (key.clone(), value.cumulative_latency_ns));
            match candidate {
                Some((candidate_key, candidate_metric)) if latency_ns > candidate_metric => {
                    self.entries.remove(&candidate_key);
                    self.evicted_keys = self.evicted_keys.saturating_add(1);
                }
                _ => {
                    self.evicted_keys = self.evicted_keys.saturating_add(1);
                    return;
                }
            }
        }
        let entry = self.entries.entry(key).or_default();
        entry.count = entry.count.saturating_add(1);
        entry.bytes = entry.bytes.saturating_add(bytes);
        entry.cumulative_latency_ns = entry.cumulative_latency_ns.saturating_add(latency_ns);
        entry.max_latency_ns = entry.max_latency_ns.max(latency_ns);
        entry.confidence = confidence.or(entry.confidence);
    }

    fn snapshot(&self, epoch: u64, dimension: HeavyHitterDimension) -> HeavyHitterSnapshot {
        let mut entries = self
            .entries
            .iter()
            .map(|(key, value)| HeavyHitterEntry {
                key: key.clone(),
                count: value.count,
                bytes: value.bytes,
                cumulative_latency_ns: value.cumulative_latency_ns,
                max_latency_ns: value.max_latency_ns,
                confidence: value.confidence,
            })
            .collect::<Vec<_>>();
        entries.sort_unstable_by(|left, right| {
            right
                .cumulative_latency_ns
                .cmp(&left.cumulative_latency_ns)
                .then_with(|| left.key.cmp(&right.key))
        });
        entries.truncate(20);
        let covered_metric = entries
            .iter()
            .map(|entry| entry.cumulative_latency_ns)
            .sum();
        HeavyHitterSnapshot {
            epoch,
            dimension,
            metric: HeavyHitterMetric::CumulativeLatency,
            candidate_capacity: self.capacity as u32,
            evicted_keys: self.evicted_keys,
            covered_metric,
            total_metric: self.total_metric,
            entries,
        }
    }
}

#[derive(Debug)]
struct LiveHeavyHitters {
    pending: HashMap<u64, BlockIssue>,
    processes: BoundedTop,
    files: BoundedTop,
}

#[derive(Debug)]
struct BufferedRecord {
    ts_ns: u64,
    encoded_bytes: usize,
    record: WireRecord,
}

#[derive(Debug)]
struct FlightRecorder {
    max_bytes: usize,
    window_ns: u64,
    bytes: usize,
    evicted_records: u64,
    records: VecDeque<BufferedRecord>,
}

impl FlightRecorder {
    fn new(max_bytes: usize, window_ns: u64) -> Self {
        Self {
            max_bytes,
            window_ns,
            bytes: 0,
            evicted_records: 0,
            records: VecDeque::new(),
        }
    }

    fn observe(&mut self, ts_ns: u64, record: WireRecord) {
        let encoded_bytes = serde_json::to_vec(&record).map_or(0, |value| value.len() + 1);
        if encoded_bytes > self.max_bytes {
            self.evicted_records = self.evicted_records.saturating_add(1);
            return;
        }
        self.bytes = self.bytes.saturating_add(encoded_bytes);
        self.records.push_back(BufferedRecord {
            ts_ns,
            encoded_bytes,
            record,
        });
        let minimum_ts = ts_ns.saturating_sub(self.window_ns);
        while self.bytes > self.max_bytes
            || self
                .records
                .front()
                .is_some_and(|record| record.ts_ns < minimum_ts)
        {
            if let Some(record) = self.records.pop_front() {
                self.bytes = self.bytes.saturating_sub(record.encoded_bytes);
                self.evicted_records = self.evicted_records.saturating_add(1);
            } else {
                break;
            }
        }
    }

    fn retained_start(&self, requested_start_ts_ns: u64) -> u64 {
        self.records
            .iter()
            .find(|record| record.ts_ns >= requested_start_ts_ns)
            .map_or(requested_start_ts_ns, |record| record.ts_ns)
    }

    fn retained_bytes(&self) -> u64 {
        self.bytes as u64
    }

    fn retained_record_count(&self) -> usize {
        self.records
            .iter()
            .filter(|record| matches!(&record.record, WireRecord::Event { .. }))
            .count()
    }
}

#[derive(Debug)]
struct ActiveSegment {
    segment_id: u64,
    trigger_ts_ns: u64,
    requested_start_ts_ns: u64,
    retained_start_ts_ns: u64,
    evicted_at_start: u64,
}

#[derive(Debug, Default)]
struct StackCaptureHealth {
    attempts: u64,
    captured: u64,
    lookup_failures: u64,
    cohort_capacity_rejections: u64,
}

fn observe_stack_fingerprints(
    raw: &KernelEvent,
    correlation_salt: u64,
    stack_map: &StackTraceMap<MapData>,
    cohorts: &mut HashMap<(StackKind, u64), StackFingerprintRecord>,
    health: &mut StackCaptureHealth,
) {
    for (kind, stack_id) in [
        (StackKind::Kernel, raw.kernel_stack_id),
        (StackKind::User, raw.user_stack_id),
    ] {
        if stack_id == STACK_ID_UNAVAILABLE {
            continue;
        }
        health.attempts = health.attempts.saturating_add(1);
        let opaque_stack_id = opaque_key(
            stack_id
                ^ if kind == StackKind::User {
                    1_u64 << 63
                } else {
                    0
                },
            correlation_salt,
        );
        let key = (kind, opaque_stack_id);
        if !cohorts.contains_key(&key) && cohorts.len() >= 4_096 {
            health.cohort_capacity_rejections = health.cohort_capacity_rejections.saturating_add(1);
            continue;
        }
        let frame_count = match stack_map.get(&(stack_id as u32), 0) {
            Ok(trace) => trace.frames().len() as u32,
            Err(_) => {
                health.lookup_failures = health.lookup_failures.saturating_add(1);
                0
            }
        };
        if frame_count != 0 {
            health.captured = health.captured.saturating_add(1);
        }
        let latency_ns = raw.ts_ns.saturating_sub(raw.start_ts_ns);
        let entry = cohorts.entry(key).or_insert(StackFingerprintRecord {
            ts_ns: raw.ts_ns,
            transaction_id: (raw.request_id != 0)
                .then(|| opaque_key(raw.request_id, correlation_salt)),
            kind,
            opaque_stack_id,
            frame_count,
            symbolized: false,
            sample_count: 0,
            tail_count: 0,
            cumulative_latency_ns: 0,
        });
        entry.ts_ns = raw.ts_ns;
        entry.frame_count = entry.frame_count.max(frame_count);
        entry.sample_count = entry.sample_count.saturating_add(1);
        entry.tail_count = entry
            .tail_count
            .saturating_add(u64::from(latency_ns >= 5_000_000));
        entry.cumulative_latency_ns = entry.cumulative_latency_ns.saturating_add(latency_ns);
    }
}

impl LiveHeavyHitters {
    fn new(capacity: usize) -> Self {
        Self {
            pending: HashMap::new(),
            processes: BoundedTop::new(capacity),
            files: BoundedTop::new(capacity),
        }
    }

    fn observe(&mut self, event: &StorageEvent) {
        match event {
            StorageEvent::BlockIssue(issue) => {
                self.pending.insert(issue.request_id, issue.clone());
            }
            StorageEvent::BlockComplete(completion) => {
                if let Some(issue) = self.pending.remove(&completion.request_id) {
                    let latency = completion.ts_ns.saturating_sub(issue.ts_ns);
                    self.processes.observe(
                        format!("{} ({})", issue.comm, issue.pid),
                        issue.bytes as u64,
                        latency,
                        None,
                    );
                }
            }
            StorageEvent::FileIo(file) => {
                let key = file
                    .path_snapshot
                    .as_ref()
                    .and_then(|snapshot| snapshot.path.clone())
                    .or_else(|| file.path.clone())
                    .or_else(|| {
                        file.file_identity
                            .as_ref()
                            .map(|identity| identity.fallback_label())
                    })
                    .unwrap_or_else(|| "Unattributed".into());
                let confidence = match file.confidence {
                    AttributionConfidence::Exact => Some(EdgeConfidence::Exact),
                    AttributionConfidence::Attributed => Some(EdgeConfidence::Probable),
                    _ => None,
                };
                self.files.observe(
                    key,
                    file.completed_bytes.max(0) as u64,
                    file.end_ts_ns.saturating_sub(file.start_ts_ns),
                    confidence,
                );
            }
            _ => {}
        }
    }
}

impl FilterMaps {
    fn take(bpf: &mut Ebpf) -> Result<Self> {
        Ok(Self {
            active: Array::try_from(
                bpf.take_map("FILTER_ACTIVE")
                    .context("FILTER_ACTIVE map is missing")?,
            )?,
            configs: UserHashMap::try_from(
                bpf.take_map("FILTER_CONFIGS")
                    .context("FILTER_CONFIGS map is missing")?,
            )?,
            pids: UserHashMap::try_from(
                bpf.take_map("FILTER_PIDS")
                    .context("FILTER_PIDS map is missing")?,
            )?,
            tids: UserHashMap::try_from(
                bpf.take_map("FILTER_TIDS")
                    .context("FILTER_TIDS map is missing")?,
            )?,
            uids: UserHashMap::try_from(
                bpf.take_map("FILTER_UIDS")
                    .context("FILTER_UIDS map is missing")?,
            )?,
            devices: UserHashMap::try_from(
                bpf.take_map("FILTER_DEVICES")
                    .context("FILTER_DEVICES map is missing")?,
            )?,
            operations: UserHashMap::try_from(
                bpf.take_map("FILTER_OPERATIONS")
                    .context("FILTER_OPERATIONS map is missing")?,
            )?,
        })
    }

    fn apply(&mut self, config: &CaptureConfig) -> Result<()> {
        if !config.filter.files.is_empty() {
            bail!("file identity filter is unavailable without a direct VFS file identity probe")
        }
        let generation = config.generation;
        insert_filter_values(
            &mut self.pids,
            generation,
            config.filter.pids.iter().map(|v| *v as u64),
        )?;
        insert_filter_values(
            &mut self.tids,
            generation,
            config.filter.tids.iter().map(|v| *v as u64),
        )?;
        insert_filter_values(
            &mut self.uids,
            generation,
            config.filter.uids.iter().map(|v| *v as u64),
        )?;
        insert_filter_values(
            &mut self.devices,
            generation,
            config
                .filter
                .devices
                .iter()
                .map(|&(major, minor)| encode_device(major, minor) as u64),
        )?;
        insert_filter_values(
            &mut self.operations,
            generation,
            config
                .filter
                .operations
                .iter()
                .map(|value| operation_code(*value) as u64),
        )?;
        let raw = RawFilterConfig {
            generation,
            total_latency_ns: config.detail.total_latency_ns,
            queue_latency_ns: config.detail.queue_latency_ns,
            device_latency_ns: config.detail.device_latency_ns,
            min_bytes: config.filter.min_bytes.unwrap_or(0),
            max_bytes: config.filter.max_bytes.unwrap_or(0),
            pid_count: config.filter.pids.len() as u16,
            tid_count: config.filter.tids.len() as u16,
            uid_count: config.filter.uids.len() as u16,
            device_count: config.filter.devices.len() as u16,
            operation_count: config.filter.operations.len() as u16,
            sample_rate_permyriad: config.detail.sample_rate_permyriad,
            mode: capture_mode_code(config.mode),
            match_all: u8::from(config.filter.match_all),
            include_errors: u8::from(config.detail.include_errors),
            include_correlation_failures: u8::from(config.detail.include_correlation_failures),
        };
        self.configs
            .insert(generation, RawFilterConfigValue(raw), 0)
            .context("cannot stage filter config")?;
        self.active
            .set(0, generation, 0)
            .context("cannot activate filter generation")?;
        Ok(())
    }
}

fn insert_filter_values(
    map: &mut UserHashMap<MapData, FilterKeyValue, u8>,
    generation: u64,
    values: impl Iterator<Item = u64>,
) -> Result<()> {
    for value in values {
        map.insert(FilterKeyValue(FilterKey { generation, value }), 1, 0)
            .context("cannot stage filter key")?;
    }
    Ok(())
}

fn capture_mode_code(mode: CaptureMode) -> u8 {
    match mode {
        CaptureMode::Basic => MODE_BASIC,
        CaptureMode::Balanced => MODE_BALANCED,
        CaptureMode::Deep => MODE_DEEP,
        CaptureMode::RawAll => MODE_RAW_ALL,
    }
}

fn operation_code(operation: IoOperation) -> u8 {
    match operation {
        IoOperation::Read => OP_READ,
        IoOperation::Write => OP_WRITE,
        IoOperation::Flush => OP_FLUSH,
        IoOperation::Discard => OP_DISCARD,
        IoOperation::Other => OP_OTHER,
    }
}

fn encode_device(major: u32, minor: u32) -> u32 {
    (major << 8) | (minor & 0xff) | ((minor & 0x0fff00) << 12)
}

fn default_capture_config() -> CaptureConfig {
    CaptureConfig {
        generation: 1,
        mode: CaptureMode::Balanced,
        filter: CaptureFilter {
            match_all: true,
            ..CaptureFilter::default()
        },
        detail: DetailPolicy::default(),
        trigger: Some(android_ebpf_protocol::TriggerPolicy {
            rule: "p99_total_latency".into(),
            threshold: 5_000_000,
            consecutive_windows: 3,
            deep_duration_ns: 10_000_000_000,
            cooldown_ns: 10_000_000_000,
            arming_timeout_ns: 5_000_000_000,
        }),
    }
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Probe => emit_probe(),
        Command::Capture {
            bpf_object,
            health_interval_ms,
            session_id,
            log_level,
        } => {
            LOG_LEVEL.store(
                match log_level {
                    LogLevelArg::Info => 2,
                    LogLevelArg::Debug => 3,
                    LogLevelArg::Trace => 4,
                },
                Ordering::Relaxed,
            );
            capture(&bpf_object, health_interval_ms, &session_id)
        }
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

fn capture(object: &Path, health_interval_ms: u64, session_id: &str) -> Result<()> {
    if health_interval_ms == 0 {
        bail!("health interval must be positive")
    }
    let mut config = capabilities()?;
    if !config.capabilities.block_issue || !config.capabilities.block_complete {
        bail!("mandatory block tracepoints are not available")
    }
    emit_diagnostic(
        session_id,
        DiagnosticLevel::Info,
        "capture.lifecycle",
        "CAPTURE_ATTACHING",
        "started",
        None,
    );
    let mut bpf = required_step(
        session_id,
        "bpf.load",
        "PROBE_LOAD_FAILED",
        Ebpf::load_file(object)
            .with_context(|| format!("failed to load eBPF object {}", object.display())),
    )?;
    required_step(
        session_id,
        "probe.configure",
        "LAYOUT_CONFIG_FAILED",
        configure_layout(&mut bpf, "ISSUE_LAYOUT", config.issue),
    )?;
    required_step(
        session_id,
        "probe.configure",
        "LAYOUT_CONFIG_FAILED",
        configure_layout(&mut bpf, "COMPLETE_LAYOUT", config.complete),
    )?;
    required_step(
        session_id,
        "probe.attach",
        "PROBE_ATTACH_FAILED",
        attach(&mut bpf, "block_rq_issue", "block", "block_rq_issue"),
    )?;
    required_step(
        session_id,
        "probe.attach",
        "PROBE_ATTACH_FAILED",
        attach(&mut bpf, "block_rq_complete", "block", "block_rq_complete"),
    )?;
    if let Some(layout) = config.insert {
        let result = configure_layout(&mut bpf, "INSERT_LAYOUT", layout)
            .and_then(|_| attach(&mut bpf, "block_rq_insert", "block", "block_rq_insert"));
        if !emit_optional_probe_result(
            session_id,
            PipelineLayer::BlockQueue,
            "block/block_rq_insert",
            result,
        ) {
            config.capabilities.block_insert = false;
            mark_attach_failed(
                &mut config.capabilities,
                PipelineLayer::BlockQueue,
                "block_rq_insert",
                true,
            );
        }
    }
    if let Some(layout) = config.syscall {
        let result = configure_syscall_layout(&mut bpf, layout)
            .and_then(|_| attach(&mut bpf, "raw_sys_enter", "raw_syscalls", "sys_enter"))
            .and_then(|_| attach(&mut bpf, "raw_sys_exit", "raw_syscalls", "sys_exit"));
        if !emit_optional_probe_result(
            session_id,
            PipelineLayer::Syscall,
            "raw_syscalls/sys_enter+sys_exit",
            result,
        ) {
            config.capabilities.file_io = false;
            mark_attach_failed(
                &mut config.capabilities,
                PipelineLayer::Syscall,
                "sys_enter/sys_exit",
                true,
            );
        }
    }
    let mut failed_optional = Vec::new();
    for probe in &config.pipeline_probes {
        let result =
            configure_pipeline_layout(&mut bpf, probe.map_name, probe.layout).and_then(|_| {
                attach(
                    &mut bpf,
                    probe.program_name,
                    &probe.group,
                    &probe.event_name,
                )
            });
        match result {
            Ok(()) => emit_diagnostic(
                session_id,
                DiagnosticLevel::Info,
                "probe.attach",
                "PROBE_ATTACHED",
                "success",
                Some(format!(
                    "layer={:?} probe={}/{} format_hash={}",
                    probe.layer, probe.group, probe.event_name, probe.format_hash
                )),
            ),
            Err(error) => {
                failed_optional.push((probe.layer, probe.event_name.clone(), true));
                emit_diagnostic(
                    session_id,
                    DiagnosticLevel::Warn,
                    "probe.attach",
                    "PROBE_ATTACH_FAILED",
                    "unavailable",
                    Some(format!(
                        "layer={:?} probe={}/{} error={error:#}",
                        probe.layer, probe.group, probe.event_name
                    )),
                )
            }
        }
    }
    for probe in &config.context_probes {
        match attach(
            &mut bpf,
            probe.program_name,
            &probe.group,
            &probe.event_name,
        ) {
            Ok(()) => emit_diagnostic(
                session_id,
                DiagnosticLevel::Info,
                "probe.attach",
                "PROBE_ATTACHED",
                "success",
                Some(format!(
                    "layer={:?} probe={}/{} format_hash={}",
                    probe.layer, probe.group, probe.event_name, probe.format_hash
                )),
            ),
            Err(error) => {
                failed_optional.push((probe.layer, probe.event_name.clone(), false));
                emit_diagnostic(
                    session_id,
                    DiagnosticLevel::Warn,
                    "probe.attach",
                    "PROBE_ATTACH_FAILED",
                    "unavailable",
                    Some(format!(
                        "layer={:?} probe={}/{} error={error:#}",
                        probe.layer, probe.group, probe.event_name
                    )),
                )
            }
        }
    }
    for (layer, event, whole_layer) in failed_optional {
        mark_attach_failed(&mut config.capabilities, layer, &event, whole_layer);
    }
    let mut active_config = default_capture_config();
    let mut requested_mode = active_config.mode;
    let mut adaptive_controller = active_config
        .trigger
        .clone()
        .map(AdaptiveController::new)
        .transpose()?;
    let mut filter_maps = FilterMaps::take(&mut bpf)?;
    filter_maps
        .apply(&active_config)
        .context("cannot apply initial capture filter")?;
    let aggregate_map = bpf
        .take_map("AGGREGATES")
        .context("AGGREGATES map is missing")?;
    let aggregates = PerCpuArray::<_, KernelAggregateValue>::try_from(aggregate_map)?;
    let stack_trace_map = bpf
        .take_map("STACK_TRACES")
        .context("STACK_TRACES map is missing")?;
    let stack_traces = StackTraceMap::try_from(stack_trace_map)?;
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
    emit_diagnostic(
        session_id,
        DiagnosticLevel::Info,
        "capture.lifecycle",
        "CAPTURE_RUNNING",
        "success",
        None,
    );

    let (control_tx, control_rx) = mpsc::channel::<CaptureControlCommand>();
    let control_session = session_id.to_owned();
    thread::spawn(move || read_control_commands(&control_session, control_tx));
    let health_interval = Duration::from_millis(health_interval_ms);
    let mut last_health = Instant::now();
    let mut sequence = 0_u64;
    let mut emitted = 0_u64;
    let mut rejected = 0_u64;
    let mut probe_health = BTreeMap::new();
    let mut pending_stage = HashMap::<(PipelineLayer, u64), u64>::new();
    let mut ambiguous_stage = HashMap::<(PipelineLayer, u64), u64>::new();
    let mut expired_stage = 0_u64;
    let mut reused_stage = 0_u64;
    let mut aggregate_epoch = 0_u64;
    let mut live_top = LiveHeavyHitters::new(256);
    let mut flight_recorder = FlightRecorder::new(32 * 1024 * 1024, 5_000_000_000);
    let mut active_segment: Option<ActiveSegment> = None;
    let mut next_segment_id = 1_u64;
    let mut stack_cohorts = HashMap::<(StackKind, u64), StackFingerprintRecord>::new();
    let mut stack_health = StackCaptureHealth::default();
    let correlation_salt = format_hash64(session_id.as_bytes());
    while running.load(Ordering::Acquire) {
        for command in control_rx.try_iter() {
            let previous_config = active_config.clone();
            let mut acknowledgement = apply_control_command(&mut active_config, command);
            if acknowledgement.outcome == ControlOutcome::Applied
                && let Err(error) = filter_maps.apply(&active_config)
            {
                active_config = previous_config;
                acknowledgement.active_generation = active_config.generation;
                acknowledgement.outcome = ControlOutcome::Rejected;
                acknowledgement.reason = Some(error.to_string());
            }
            if acknowledgement.outcome == ControlOutcome::Applied {
                requested_mode = active_config.mode;
                adaptive_controller = active_config
                    .trigger
                    .clone()
                    .map(AdaptiveController::new)
                    .transpose()?;
            }
            let applied = acknowledgement.outcome == ControlOutcome::Applied;
            emit_diagnostic(
                session_id,
                if applied {
                    DiagnosticLevel::Info
                } else {
                    DiagnosticLevel::Warn
                },
                "capture.control",
                if applied {
                    "FILTER_UPDATE_APPLIED"
                } else {
                    "FILTER_UPDATE_REJECTED"
                },
                if applied { "applied" } else { "rejected" },
                Some(format!(
                    "requested_generation={} active_generation={} reason={}",
                    acknowledgement.requested_generation,
                    acknowledgement.active_generation,
                    acknowledgement.reason.as_deref().unwrap_or("none")
                )),
            );
            write_record(
                &mut output,
                &WireRecord::Control {
                    schema_version: SCHEMA_VERSION,
                    acknowledgement,
                },
            )?;
            output.flush()?;
        }
        let mut had_event = false;
        while let Some(item) = ring.next() {
            had_event = true;
            let raw_event = decode_kernel_event(&item);
            match raw_event
                .and_then(|raw| parse_kernel_event(raw, correlation_salt).map(|event| (raw, event)))
            {
                Some((raw, event)) => {
                    observe_stack_fingerprints(
                        &raw,
                        correlation_salt,
                        &stack_traces,
                        &mut stack_cohorts,
                        &mut stack_health,
                    );
                    live_top.observe(&event);
                    update_probe_health(
                        session_id,
                        &event,
                        &mut probe_health,
                        &mut pending_stage,
                        &mut ambiguous_stage,
                        &mut expired_stage,
                        &mut reused_stage,
                    );
                    sequence += 1;
                    emit_event_trace(session_id, sequence, &event);
                    let event_ts_ns = storage_event_timestamp(&event);
                    let record = WireRecord::Event {
                        schema_version: SCHEMA_VERSION,
                        sequence,
                        event,
                    };
                    flight_recorder.observe(event_ts_ns, record.clone());
                    write_record(&mut output, &record)?;
                    emitted += 1;
                }
                None => rejected += 1,
            }
        }
        if last_health.elapsed() >= health_interval {
            aggregate_epoch = aggregate_epoch.saturating_add(1);
            let aggregate_snapshot = read_aggregate_snapshot(
                session_id,
                aggregate_epoch,
                active_config.generation,
                &aggregates,
            )
            .ok();
            if let Some(snapshot) = &aggregate_snapshot {
                let aggregate_record = WireRecord::Aggregate {
                    schema_version: SCHEMA_VERSION,
                    snapshot: snapshot.clone(),
                };
                flight_recorder.observe(snapshot.end_ts_ns, aggregate_record.clone());
                write_record(&mut output, &aggregate_record)?;
                if let Some(controller) = adaptive_controller.as_mut()
                    && let Some(observed) =
                        aggregate_percentile_upper(snapshot, HistogramMetric::TotalLatency, 99)
                    && let Some(mut trigger) =
                        controller.observe(snapshot.end_ts_ns, observed, active_config.generation)
                {
                    let target_mode = match trigger.to {
                        CaptureState::Deep => Some(CaptureMode::Deep),
                        CaptureState::Cooldown => Some(CaptureMode::Balanced),
                        CaptureState::Basic => Some(requested_mode),
                        CaptureState::Armed => None,
                    };
                    if let Some(target_mode) = target_mode
                        && active_config.mode != target_mode
                    {
                        let mut automatic = active_config.clone();
                        automatic.generation = automatic.generation.saturating_add(1);
                        automatic.mode = target_mode;
                        filter_maps
                            .apply(&automatic)
                            .context("cannot apply adaptive capture transition")?;
                        active_config = automatic;
                        trigger.config_generation = active_config.generation;
                    }
                    if trigger.to == CaptureState::Deep {
                        let requested_start_ts_ns = trigger.ts_ns.saturating_sub(3_000_000_000);
                        active_segment = Some(ActiveSegment {
                            segment_id: next_segment_id,
                            trigger_ts_ns: trigger.ts_ns,
                            requested_start_ts_ns,
                            retained_start_ts_ns: flight_recorder
                                .retained_start(requested_start_ts_ns),
                            evicted_at_start: flight_recorder.evicted_records,
                        });
                        next_segment_id = next_segment_id.saturating_add(1);
                    }
                    emit_diagnostic(
                        session_id,
                        DiagnosticLevel::Info,
                        "capture.adaptive",
                        "CAPTURE_STATE_TRANSITION",
                        "applied",
                        Some(format!(
                            "from={:?} to={:?} rule={} observed={} threshold={} generation={}",
                            trigger.from,
                            trigger.to,
                            trigger.rule,
                            trigger.observed,
                            trigger.threshold,
                            trigger.config_generation
                        )),
                    );
                    let transition_to = trigger.to;
                    let transition_ts_ns = trigger.ts_ns;
                    write_record(
                        &mut output,
                        &WireRecord::Trigger {
                            schema_version: SCHEMA_VERSION,
                            trigger,
                        },
                    )?;
                    if transition_to == CaptureState::Cooldown
                        && let Some(segment) = active_segment.take()
                    {
                        let segment_record = SegmentRecord {
                            segment_id: segment.segment_id,
                            trigger_ts_ns: segment.trigger_ts_ns,
                            requested_start_ts_ns: segment.requested_start_ts_ns,
                            retained_start_ts_ns: segment.retained_start_ts_ns,
                            end_ts_ns: transition_ts_ns,
                            retained_bytes: flight_recorder.retained_bytes(),
                            evicted_records: flight_recorder
                                .evicted_records
                                .saturating_sub(segment.evicted_at_start),
                        };
                        emit_diagnostic(
                            session_id,
                            DiagnosticLevel::Info,
                            "capture.flight_recorder",
                            "FLIGHT_SEGMENT_FINALIZED",
                            "success",
                            Some(format!(
                                "segment={} retained_records={} retained_bytes={} evicted={}",
                                segment_record.segment_id,
                                flight_recorder.retained_record_count(),
                                segment_record.retained_bytes,
                                segment_record.evicted_records
                            )),
                        );
                        write_record(
                            &mut output,
                            &WireRecord::Segment {
                                schema_version: SCHEMA_VERSION,
                                segment: segment_record,
                            },
                        )?;
                    }
                }
            }
            for snapshot in [
                live_top
                    .processes
                    .snapshot(aggregate_epoch, HeavyHitterDimension::Process),
                live_top
                    .files
                    .snapshot(aggregate_epoch, HeavyHitterDimension::File),
            ] {
                write_record(
                    &mut output,
                    &WireRecord::HeavyHitters {
                        schema_version: SCHEMA_VERSION,
                        snapshot,
                    },
                )?;
            }
            for fingerprint in stack_cohorts.values() {
                write_record(
                    &mut output,
                    &WireRecord::StackFingerprint {
                        schema_version: SCHEMA_VERSION,
                        fingerprint: fingerprint.clone(),
                    },
                )?;
            }
            if stack_health.attempts != 0 || stack_health.cohort_capacity_rejections != 0 {
                emit_diagnostic(
                    session_id,
                    DiagnosticLevel::Debug,
                    "capture.stack",
                    "STACK_CAPTURE_HEALTH",
                    "observed",
                    Some(format!(
                        "attempts={} captured={} lookup_failures={} capacity_rejections={} cohorts={}",
                        stack_health.attempts,
                        stack_health.captured,
                        stack_health.lookup_failures,
                        stack_health.cohort_capacity_rejections,
                        stack_cohorts.len()
                    )),
                );
            }
            write_record(
                &mut output,
                &WireRecord::Health {
                    schema_version: SCHEMA_VERSION,
                    emitted_events: emitted,
                    kernel_drops: aggregate_snapshot
                        .as_ref()
                        .map(|snapshot| snapshot.counters.ring_reserve_failures),
                    userspace_drops: rejected,
                    probe_health: probe_health.clone(),
                    correlation_ambiguous: 0,
                    correlation_expired: expired_stage,
                    key_reused: reused_stage,
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
            graceful: Some(true),
        },
    )?;
    output.flush()?;
    emit_diagnostic(
        session_id,
        DiagnosticLevel::Info,
        "capture.lifecycle",
        "CAPTURE_COMPLETED",
        "success",
        Some(format!("emitted={emitted} rejected={rejected}")),
    );
    Ok(())
}

fn read_control_commands(session_id: &str, tx: mpsc::Sender<CaptureControlCommand>) {
    for line in BufReader::new(std::io::stdin().lock()).lines() {
        let command = match line {
            Ok(line) if line.len() <= 64 * 1024 => {
                match serde_json::from_str::<CaptureControlCommand>(&line) {
                    Ok(command) => command,
                    Err(error) => {
                        emit_diagnostic(
                            session_id,
                            DiagnosticLevel::Warn,
                            "capture.control",
                            "CONTROL_DECODE_REJECTED",
                            "rejected",
                            Some(error.to_string()),
                        );
                        continue;
                    }
                }
            }
            Ok(_) => {
                emit_diagnostic(
                    session_id,
                    DiagnosticLevel::Warn,
                    "capture.control",
                    "CONTROL_LINE_TOO_LARGE",
                    "rejected",
                    None,
                );
                continue;
            }
            Err(error) => {
                emit_diagnostic(
                    session_id,
                    DiagnosticLevel::Warn,
                    "capture.control",
                    "CONTROL_READ_FAILED",
                    "failed",
                    Some(error.to_string()),
                );
                break;
            }
        };
        if tx.send(command).is_err() {
            break;
        }
    }
}

fn read_aggregate_snapshot(
    session_id: &str,
    epoch: u64,
    generation: u64,
    map: &PerCpuArray<MapData, KernelAggregateValue>,
) -> Result<AggregateSnapshot> {
    let values = map.get(&0, 0).context("cannot read per-CPU aggregates")?;
    let mut merged = KernelAggregate {
        generation,
        ..KernelAggregate::default()
    };
    for wrapped in values.iter() {
        let value = &wrapped.0;
        if value.generation != generation {
            continue;
        }
        if value.first_ts_ns != 0 {
            merged.first_ts_ns = if merged.first_ts_ns == 0 {
                value.first_ts_ns
            } else {
                merged.first_ts_ns.min(value.first_ts_ns)
            };
        }
        merged.last_ts_ns = merged.last_ts_ns.max(value.last_ts_ns);
        merged.observed = merged.observed.saturating_add(value.observed);
        merged.bytes = merged.bytes.saturating_add(value.bytes);
        merged.failed = merged.failed.saturating_add(value.failed);
        merged.filter_passed = merged.filter_passed.saturating_add(value.filter_passed);
        merged.filter_suppressed = merged
            .filter_suppressed
            .saturating_add(value.filter_suppressed);
        merged.detail_emitted = merged.detail_emitted.saturating_add(value.detail_emitted);
        merged.suppressed_fast = merged.suppressed_fast.saturating_add(value.suppressed_fast);
        merged.sampled = merged.sampled.saturating_add(value.sampled);
        merged.forced_error = merged.forced_error.saturating_add(value.forced_error);
        merged.ring_reserve_failures = merged
            .ring_reserve_failures
            .saturating_add(value.ring_reserve_failures);
        merged.map_insert_failures = merged
            .map_insert_failures
            .saturating_add(value.map_insert_failures);
        merged.expired = merged.expired.saturating_add(value.expired);
        merged.key_reused = merged.key_reused.saturating_add(value.key_reused);
        for index in 0..HISTOGRAM_BUCKETS {
            merged.total_latency[index] =
                merged.total_latency[index].saturating_add(value.total_latency[index]);
            merged.queue_latency[index] =
                merged.queue_latency[index].saturating_add(value.queue_latency[index]);
            merged.device_latency[index] =
                merged.device_latency[index].saturating_add(value.device_latency[index]);
            merged.io_size[index] = merged.io_size[index].saturating_add(value.io_size[index]);
            merged.queue_depth[index] =
                merged.queue_depth[index].saturating_add(value.queue_depth[index]);
        }
    }
    let boundaries = log2_histogram_boundaries();
    Ok(AggregateSnapshot {
        session_id: session_id.into(),
        epoch,
        config_generation: generation,
        start_ts_ns: merged.first_ts_ns,
        end_ts_ns: merged.last_ts_ns,
        counters: AggregateCounters {
            observed: merged.observed,
            bytes: merged.bytes,
            failed: merged.failed,
            filter_passed: merged.filter_passed,
            filter_suppressed: merged.filter_suppressed,
            detail_emitted: merged.detail_emitted,
            suppressed_fast: merged.suppressed_fast,
            sampled: merged.sampled,
            forced_error: merged.forced_error,
            ring_reserve_failures: merged.ring_reserve_failures,
            map_insert_failures: merged.map_insert_failures,
            expired: merged.expired,
            key_reused: merged.key_reused,
        },
        histograms: vec![
            (
                HistogramMetric::TotalLatency,
                Histogram {
                    boundaries: boundaries.clone(),
                    counts: merged.total_latency.to_vec(),
                },
            ),
            (
                HistogramMetric::QueueLatency,
                Histogram {
                    boundaries: boundaries.clone(),
                    counts: merged.queue_latency.to_vec(),
                },
            ),
            (
                HistogramMetric::DeviceLatency,
                Histogram {
                    boundaries: boundaries.clone(),
                    counts: merged.device_latency.to_vec(),
                },
            ),
            (
                HistogramMetric::IoSize,
                Histogram {
                    boundaries,
                    counts: merged.io_size.to_vec(),
                },
            ),
        ],
    })
}

fn log2_histogram_boundaries() -> Vec<u64> {
    (0..HISTOGRAM_BUCKETS - 1)
        .map(|index| (1_u64 << (index + 1)).saturating_sub(1))
        .collect()
}

fn aggregate_percentile_upper(
    snapshot: &AggregateSnapshot,
    metric: HistogramMetric,
    percentile: u8,
) -> Option<u64> {
    snapshot
        .histograms
        .iter()
        .find(|(candidate, _)| *candidate == metric)
        .and_then(|(_, histogram)| histogram.percentile_range(percentile))
        .map(|(lower, upper)| upper.unwrap_or(lower))
}

fn apply_control_command(
    active: &mut CaptureConfig,
    command: CaptureControlCommand,
) -> CaptureControlAck {
    let requested = match command {
        CaptureControlCommand::ApplyConfig { config } => config,
        CaptureControlCommand::SetMode {
            generation,
            mode,
            reason: _,
        } => CaptureConfig {
            generation,
            mode,
            filter: active.filter.clone(),
            detail: active.detail.clone(),
            trigger: active.trigger.clone(),
        },
    };
    let rejected_reason = if requested.generation <= active.generation {
        Some("generation must increase".to_owned())
    } else {
        requested.validate(256).err().map(|error| error.to_string())
    };
    if let Some(reason) = rejected_reason {
        return CaptureControlAck {
            requested_generation: requested.generation,
            active_generation: active.generation,
            outcome: ControlOutcome::Rejected,
            reason: Some(reason),
        };
    }
    let requested_generation = requested.generation;
    *active = requested;
    CaptureControlAck {
        requested_generation,
        active_generation: requested_generation,
        outcome: ControlOutcome::Applied,
        reason: None,
    }
}

fn emit_optional_probe_result(
    session_id: &str,
    layer: PipelineLayer,
    probe: &str,
    result: Result<()>,
) -> bool {
    match result {
        Ok(()) => {
            emit_diagnostic(
                session_id,
                DiagnosticLevel::Info,
                "probe.attach",
                "PROBE_ATTACHED",
                "success",
                Some(format!("layer={layer:?} probe={probe}")),
            );
            true
        }
        Err(error) => {
            emit_diagnostic(
                session_id,
                DiagnosticLevel::Warn,
                "probe.attach",
                "PROBE_ATTACH_FAILED",
                "unavailable",
                Some(format!("layer={layer:?} probe={probe} error={error:#}")),
            );
            false
        }
    }
}

fn mark_attach_failed(
    capabilities: &mut ProbeCapabilities,
    layer: PipelineLayer,
    event: &str,
    whole_layer: bool,
) {
    for plan in capabilities.attach_plan.iter_mut().filter(|plan| {
        plan.layer == layer && (whole_layer || plan.event_or_function.contains(event))
    }) {
        plan.state = CapabilityState::Unavailable;
        plan.reason = Some("runtime attach failed; see structured diagnostic log".into());
    }
    if !capabilities
        .attach_plan
        .iter()
        .any(|plan| plan.layer == layer && plan.state != CapabilityState::Unavailable)
    {
        capabilities.pipeline_layers.retain(|value| *value != layer);
    }
}

fn required_step<T>(session_id: &str, event: &str, code: &str, result: Result<T>) -> Result<T> {
    if let Err(error) = &result {
        emit_diagnostic(
            session_id,
            DiagnosticLevel::Error,
            event,
            code,
            "failed",
            Some(format!("{error:#}")),
        );
    }
    result
}

fn emit_event_trace(session_id: &str, sequence: u64, event: &StorageEvent) {
    if LOG_LEVEL.load(Ordering::Relaxed) < 4 {
        return;
    }
    let (component, correlation_id, node_id, detail) = match event {
        StorageEvent::BlockInsert(value) => ("block", Some(value.request_id), None, "insert"),
        StorageEvent::BlockIssue(value) => ("block", Some(value.request_id), None, "issue"),
        StorageEvent::BlockComplete(value) => ("block", Some(value.request_id), None, "complete"),
        StorageEvent::FileIo(value) => ("file", None, value.node_id, "syscall"),
        StorageEvent::Pipeline(value) => (
            "pipeline",
            value.correlation_id.or(value.stage_key),
            None,
            "stage",
        ),
        StorageEvent::Node(value) => ("graph", value.transaction_id, Some(value.node_id), "node"),
        StorageEvent::Edge(value) => ("graph", value.transaction_id, None, "edge"),
    };
    let record = DiagnosticRecord {
        schema_version: SCHEMA_VERSION,
        ts_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_millis() as i64),
        level: DiagnosticLevel::Trace,
        component: format!("android-agent.{component}"),
        event: "capture.event".into(),
        session_id: session_id.into(),
        boot_id: read_trimmed("/proc/sys/kernel/random/boot_id").unwrap_or_default(),
        outcome: "emitted".into(),
        code: "EVENT_EMITTED".into(),
        correlation_id,
        node_id,
        probe: None,
        duration_ms: None,
        count: Some(sequence),
        detail: Some(detail.into()),
    };
    if let Ok(json) = serde_json::to_string(&record) {
        eprintln!("{json}");
    }
}

fn storage_event_timestamp(event: &StorageEvent) -> u64 {
    match event {
        StorageEvent::BlockInsert(value) => value.ts_ns,
        StorageEvent::BlockIssue(value) => value.ts_ns,
        StorageEvent::BlockComplete(value) => value.ts_ns,
        StorageEvent::FileIo(value) => value.end_ts_ns,
        StorageEvent::Pipeline(value) => value.end_ts_ns.unwrap_or(value.ts_ns),
        StorageEvent::Node(value) => value.end_or_start(),
        // Edges carry causal evidence but no timestamp. Keeping them at the
        // start of the retention window avoids inventing a measurement.
        StorageEvent::Edge(_) => 0,
    }
}

fn update_probe_health(
    session_id: &str,
    event: &StorageEvent,
    health: &mut BTreeMap<String, android_ebpf_protocol::ProbeHealth>,
    pending: &mut HashMap<(PipelineLayer, u64), u64>,
    ambiguous: &mut HashMap<(PipelineLayer, u64), u64>,
    expired: &mut u64,
    reused: &mut u64,
) {
    let (name, pipeline) = match event {
        StorageEvent::BlockInsert(_) => ("block.insert", None),
        StorageEvent::BlockIssue(_) => ("block.issue", None),
        StorageEvent::BlockComplete(_) => ("block.complete", None),
        StorageEvent::FileIo(_) => ("syscall.file_io", None),
        StorageEvent::Pipeline(value) => (
            match value.layer {
                PipelineLayer::Filesystem => "filesystem.pipeline",
                PipelineLayer::Scsi => "scsi.pipeline",
                PipelineLayer::Ufs => "ufs.pipeline",
                PipelineLayer::SchedulerContext => "scheduler.context",
                PipelineLayer::UicContext => "uic.context",
                _ => "storage.pipeline",
            },
            Some(value),
        ),
        StorageEvent::Node(_) => ("graph.node", None),
        StorageEvent::Edge(_) => ("graph.edge", None),
    };
    health.entry(name.into()).or_default().emitted += 1;
    let Some(value) = pipeline else { return };
    let Some(key) = value.stage_key.or(value.correlation_id) else {
        return;
    };
    let pair_key = (value.layer, key);
    match value.phase {
        PipelinePhase::Begin => {
            if pending.remove(&pair_key).is_some() || ambiguous.contains_key(&pair_key) {
                ambiguous.insert(pair_key, value.ts_ns);
                health.entry(name.into()).or_default().unpaired += 1;
                *reused += 1;
                if LOG_LEVEL.load(Ordering::Relaxed) >= 3 {
                    emit_diagnostic(
                        session_id,
                        DiagnosticLevel::Debug,
                        "correlation.decision",
                        "STAGE_KEY_REUSED",
                        "rejected",
                        Some(format!("layer={:?}", value.layer)),
                    );
                }
            } else {
                pending.insert(pair_key, value.ts_ns);
            }
        }
        PipelinePhase::End => {
            let item = health.entry(name.into()).or_default();
            if ambiguous.remove(&pair_key).is_some() {
                pending.remove(&pair_key);
                item.unpaired += 1;
            } else if pending.remove(&pair_key).is_some() {
                item.paired += 1;
            } else {
                item.unpaired += 1;
                if LOG_LEVEL.load(Ordering::Relaxed) >= 3 {
                    emit_diagnostic(
                        session_id,
                        DiagnosticLevel::Debug,
                        "correlation.decision",
                        "STAGE_END_UNMATCHED",
                        "rejected",
                        Some(format!("layer={:?}", value.layer)),
                    );
                }
            }
        }
        PipelinePhase::Instant | PipelinePhase::Span => {}
    }
    let newest = value.ts_ns;
    let expired_before = *expired;
    pending.retain(|_, started| {
        let keep = newest.saturating_sub(*started) <= 30_000_000_000;
        if !keep {
            *expired += 1;
        }
        keep
    });
    ambiguous.retain(|_, observed| {
        let keep = newest.saturating_sub(*observed) <= 30_000_000_000;
        if !keep {
            *expired += 1;
        }
        keep
    });
    if *expired > expired_before && LOG_LEVEL.load(Ordering::Relaxed) >= 3 {
        emit_diagnostic(
            session_id,
            DiagnosticLevel::Debug,
            "correlation.decision",
            "STAGE_KEY_EXPIRED",
            "rejected",
            Some(format!(
                "layer={:?} count={}",
                value.layer,
                *expired - expired_before
            )),
        );
    }
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
    let scsi_events = discover_events("scsi");
    let sched_events = discover_events("sched");
    let fs_events = discover_events("f2fs");
    let ext4_events = discover_events("ext4");
    let mut pipeline_probes = Vec::new();
    let mut context_probes = Vec::new();
    if let Some(event) = ufs_events
        .iter()
        .find(|event| event.ends_with("/ufshcd_command"))
        && let Some(probe) = build_pipeline_probe(
            "ufs_command",
            "UFS_LAYOUT",
            event,
            PipelineLayer::Ufs,
            &["tag"],
            &["lba"],
            &["transfer_len"],
            &["opcode"],
            &["status", "result", "scsi_status"],
            &["str"],
        )
    {
        pipeline_probes.push(probe);
    }
    if let Some(event) = ufs_events.iter().find(|event| {
        let lower = event.to_ascii_lowercase();
        lower.contains("hibern8")
            || lower.contains("uic_command")
            || lower.contains("pwr_change")
            || lower.contains("power_mode")
    }) && let Some((group, event_name)) = event.split_once('/')
    {
        let path = format!("/sys/kernel/tracing/events/{group}/{event_name}/format");
        if let Ok(format) = fs::read_to_string(path) {
            context_probes.push(ContextProbe {
                program_name: "ufs_context",
                group: group.into(),
                event_name: event_name.into(),
                layer: PipelineLayer::UicContext,
                format_hash: format_hash(&format),
            });
        }
    }
    for (program, map, event_name) in [
        (
            "scsi_dispatch_start",
            "SCSI_START_LAYOUT",
            "scsi/scsi_dispatch_cmd_start",
        ),
        (
            "scsi_dispatch_done",
            "SCSI_DONE_LAYOUT",
            "scsi/scsi_dispatch_cmd_done",
        ),
    ] {
        if scsi_events.iter().any(|event| event == event_name)
            && let Some(probe) = build_pipeline_probe(
                program,
                map,
                event_name,
                PipelineLayer::Scsi,
                &["cmd", "scsi_cmd", "driver_tag", "tag"],
                &["lba", "sector"],
                &["bytes", "nr_bytes"],
                &["opcode"],
                &["result", "status", "scsi_status"],
                &[],
            )
        {
            pipeline_probes.push(probe);
        }
    }
    let fs_pair = [
        ("f2fs/f2fs_dataread_start", "f2fs/f2fs_dataread_end"),
        ("f2fs/f2fs_datawrite_start", "f2fs/f2fs_datawrite_end"),
    ]
    .into_iter()
    .find(|(start, done)| {
        fs_events.iter().any(|event| event == start) && fs_events.iter().any(|event| event == done)
    });
    if let Some((start, done)) = fs_pair {
        for (program, map, event_name) in [
            ("fs_data_start", "FS_START_LAYOUT", start),
            ("fs_data_done", "FS_DONE_LAYOUT", done),
        ] {
            if let Some(probe) = build_pipeline_probe(
                program,
                map,
                event_name,
                PipelineLayer::Filesystem,
                &["bio", "inode", "ino", "nid", "pblk"],
                &["offset", "lba", "sector", "pblk"],
                &["bytes", "nr_bytes", "len"],
                &[],
                &[],
                &[],
            ) {
                pipeline_probes.push(probe);
            }
        }
    }
    if let Some(event) = fs_events.iter().chain(ext4_events.iter()).find(|event| {
        let lower = event.to_ascii_lowercase();
        lower.contains("gc_")
            || lower.contains("checkpoint")
            || lower.contains("writeback")
            || lower.contains("journal")
            || lower.contains("commit")
    }) && let Some((group, event_name)) = event.split_once('/')
    {
        let path = format!("/sys/kernel/tracing/events/{group}/{event_name}/format");
        if let Ok(format) = fs::read_to_string(path) {
            context_probes.push(ContextProbe {
                program_name: "fs_context",
                group: group.into(),
                event_name: event_name.into(),
                layer: PipelineLayer::Filesystem,
                format_hash: format_hash(&format),
            });
        }
    }
    if let Some(event) = sched_events
        .iter()
        .find(|event| event.ends_with("/sched_switch"))
        && let Some((group, event_name)) = event.split_once('/')
    {
        let path = format!("/sys/kernel/tracing/events/{group}/{event_name}/format");
        if let Ok(format) = fs::read_to_string(path) {
            context_probes.push(ContextProbe {
                program_name: "sched_context",
                group: group.into(),
                event_name: event_name.into(),
                layer: PipelineLayer::SchedulerContext,
                format_hash: format_hash(&format),
            });
        }
    }
    let mut pipeline_layers = vec![PipelineLayer::BlockDevice];
    if insert.is_some() {
        pipeline_layers.push(PipelineLayer::BlockQueue);
    }
    if syscall.is_some() {
        pipeline_layers.push(PipelineLayer::Syscall);
    }
    for probe in &pipeline_probes {
        if !pipeline_layers.contains(&probe.layer) {
            pipeline_layers.push(probe.layer);
        }
    }
    for probe in &context_probes {
        if !pipeline_layers.contains(&probe.layer) {
            pipeline_layers.push(probe.layer);
        }
    }
    let mut attach_plan = vec![
        probe_plan(
            PipelineLayer::BlockDevice,
            "tracepoint",
            "block",
            "block_rq_issue",
            true,
            &issue_text,
        ),
        probe_plan(
            PipelineLayer::BlockDevice,
            "tracepoint",
            "block",
            "block_rq_complete",
            true,
            &complete_text,
        ),
    ];
    attach_plan.push(match fs::read_to_string(INSERT_FORMAT) {
        Ok(format) if insert.is_some() => probe_plan(
            PipelineLayer::BlockQueue,
            "tracepoint",
            "block",
            "block_rq_insert",
            false,
            &format,
        ),
        _ => unavailable_plan(
            PipelineLayer::BlockQueue,
            "block",
            "block_rq_insert",
            "tracepoint format unavailable or unsupported",
        ),
    });
    attach_plan.push(if syscall.is_some() {
        ProbePlan {
            layer: PipelineLayer::Syscall,
            probe_kind: "tracepoint".into(),
            group: "raw_syscalls".into(),
            event_or_function: "sys_enter/sys_exit".into(),
            state: CapabilityState::Measured,
            format_hash: Some(format_hash(&format!(
                "{}{}",
                fs::read_to_string(SYS_ENTER_FORMAT).unwrap_or_default(),
                fs::read_to_string(SYS_EXIT_FORMAT).unwrap_or_default()
            ))),
            reason: None,
        }
    } else {
        unavailable_plan(
            PipelineLayer::Syscall,
            "raw_syscalls",
            "sys_enter/sys_exit",
            "tracepoint format unavailable or unsupported",
        )
    });
    attach_plan.extend(pipeline_probes.iter().map(|probe| ProbePlan {
        layer: probe.layer,
        probe_kind: "tracepoint".into(),
        group: probe.group.clone(),
        event_or_function: probe.event_name.clone(),
        state: if probe.layer == PipelineLayer::UicContext {
            CapabilityState::Context
        } else {
            CapabilityState::Measured
        },
        format_hash: Some(probe.format_hash.clone()),
        reason: (probe.layer == PipelineLayer::Ufs).then_some(
            "UFS tag is controller-local; block association remains probable without controller identity"
                .into(),
        ),
    }));
    attach_plan.extend(context_probes.iter().map(|probe| ProbePlan {
        layer: probe.layer,
        probe_kind: "tracepoint".into(),
        group: probe.group.clone(),
        event_or_function: probe.event_name.clone(),
        state: CapabilityState::Context,
        format_hash: Some(probe.format_hash.clone()),
        reason: Some("context-only; excluded from additive latency".into()),
    }));
    for (layer, group, event, reason) in [
        (
            PipelineLayer::Vfs,
            "fentry/fprobe",
            "vfs_read/write",
            "BTF/function probe adapter not available on this kernel",
        ),
        (
            PipelineLayer::PageCache,
            "filemap",
            "page-cache events",
            "no supported page-cache tracepoint layout",
        ),
        (
            PipelineLayer::Writeback,
            "writeback",
            "writeback events",
            "no supported writeback tracepoint layout",
        ),
        (
            PipelineLayer::Bio,
            "block",
            "bio events",
            "no stable bio identity tracepoint layout",
        ),
        (
            PipelineLayer::Filesystem,
            "f2fs/ext4",
            "filesystem breakdown",
            "no supported paired filesystem tracepoints",
        ),
        (
            PipelineLayer::Scsi,
            "scsi",
            "scsi_dispatch_cmd_start/done",
            "no supported SCSI tracepoint pair",
        ),
        (
            PipelineLayer::Ufs,
            "ufs",
            "ufshcd_command",
            "no supported UFS tracepoint layout",
        ),
        (
            PipelineLayer::SchedulerContext,
            "sched",
            "sched_switch",
            "no supported scheduler context tracepoint",
        ),
        (
            PipelineLayer::UicContext,
            "ufs",
            "UIC/link context",
            "no supported UIC context tracepoint",
        ),
    ] {
        if !attach_plan.iter().any(|plan| plan.layer == layer) {
            attach_plan.push(unavailable_plan(layer, group, event, reason));
        }
    }
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
            fs_events,
            scsi_events,
            ext4_events,
            vfs_probe_candidates: if Path::new("/sys/kernel/btf/vmlinux").is_file() {
                vec![
                    "vfs_read".into(),
                    "vfs_write".into(),
                    "vfs_iter_read".into(),
                    "vfs_iter_write".into(),
                ]
            } else {
                Vec::new()
            },
            pipeline_layers,
            attach_plan,
            scheduler_context: Some(
                if sched_events
                    .iter()
                    .any(|event| event.ends_with("/sched_switch"))
                {
                    CapabilityState::Context
                } else {
                    CapabilityState::Unavailable
                },
            ),
            stack_traces: Some(CapabilityState::Measured),
        },
        issue,
        complete,
        insert,
        syscall,
        pipeline_probes,
        context_probes,
    })
}

fn unavailable_plan(layer: PipelineLayer, group: &str, event: &str, reason: &str) -> ProbePlan {
    ProbePlan {
        layer,
        probe_kind: "none".into(),
        group: group.into(),
        event_or_function: event.into(),
        state: CapabilityState::Unavailable,
        format_hash: None,
        reason: Some(reason.into()),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_pipeline_probe(
    program_name: &'static str,
    map_name: &'static str,
    event: &str,
    layer: PipelineLayer,
    key_aliases: &[&str],
    sector_aliases: &[&str],
    bytes_aliases: &[&str],
    operation_aliases: &[&str],
    status_aliases: &[&str],
    state_aliases: &[&str],
) -> Option<PipelineProbe> {
    let (group, event_name) = event.split_once('/')?;
    let path = format!("/sys/kernel/tracing/events/{group}/{event_name}/format");
    let format = fs::read_to_string(path).ok()?;
    let layout = parse_pipeline_layout(
        &format,
        key_aliases,
        sector_aliases,
        bytes_aliases,
        operation_aliases,
        status_aliases,
        state_aliases,
    )
    .ok()?;
    Some(PipelineProbe {
        program_name,
        map_name,
        group: group.into(),
        event_name: event_name.into(),
        layer,
        layout,
        format_hash: format_hash(&format),
    })
}

fn format_hash(value: &str) -> String {
    format!("fnv1a64:{:016x}", format_hash64(value.as_bytes()))
}

fn format_hash64(value: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in value {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn opaque_key(raw: u64, salt: u64) -> u64 {
    let mut value = raw ^ salt;
    value ^= value >> 33;
    value = value.wrapping_mul(0xff51_afd7_ed55_8ccd);
    value ^= value >> 33;
    value = value.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    value ^ (value >> 33)
}

fn probe_plan(
    layer: PipelineLayer,
    probe_kind: &str,
    group: &str,
    event: &str,
    required: bool,
    format: &str,
) -> ProbePlan {
    ProbePlan {
        layer,
        probe_kind: probe_kind.into(),
        group: group.into(),
        event_or_function: event.into(),
        state: CapabilityState::Measured,
        format_hash: Some(format_hash(format)),
        reason: required.then_some("mandatory".into()),
    }
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

fn configure_pipeline_layout(
    bpf: &mut Ebpf,
    name: &str,
    layout: PipelineTraceLayout,
) -> Result<()> {
    let map = bpf
        .map_mut(name)
        .with_context(|| format!("{name} map is missing"))?;
    let mut array = Array::<_, PipelineTraceLayoutValue>::try_from(map)?;
    array.set(0, PipelineTraceLayoutValue(layout), 0)?;
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

fn decode_kernel_event(bytes: &[u8]) -> Option<KernelEvent> {
    if bytes.len() < std::mem::size_of::<KernelEvent>() {
        return None;
    }
    Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<KernelEvent>()) })
}

fn parse_kernel_event(event: KernelEvent, correlation_salt: u64) -> Option<StorageEvent> {
    let (device_major, device_minor) = decode_device(event.device);
    let request_id = opaque_key(event.request_id, correlation_salt);
    match event.kind {
        KIND_BLOCK_INSERT => Some(StorageEvent::BlockInsert(BlockInsert {
            ts_ns: event.ts_ns,
            request_id,
            device_major,
            device_minor,
            sector: event.sector,
            sectors: event.sectors,
            bytes: event.bytes,
            operation: decode_operation(event.operation),
        })),
        KIND_BLOCK_ISSUE => Some(StorageEvent::BlockIssue(BlockIssue {
            ts_ns: event.ts_ns,
            request_id,
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
            request_id,
            device_major,
            device_minor,
            status: event.status,
        })),
        KIND_FILE_IO => {
            let path = resolve_fd_path(event.pid, event.fd);
            let path_snapshot = path
                .clone()
                .map(|value| android_ebpf_protocol::PathSnapshot {
                    deleted: value.ends_with(" (deleted)"),
                    path: Some(value),
                    source: android_ebpf_protocol::PathSource::ProcFd,
                    captured_ts_ns: event.ts_ns,
                });
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
                file_identity: resolve_fd_identity(event.pid, event.fd),
                path_snapshot,
                offset: resolve_fdinfo_value(event.pid, event.fd, "pos", 10).map(|position| {
                    if event.return_value > 0 {
                        position.saturating_sub(event.return_value as u64)
                    } else {
                        position
                    }
                }),
                io_mode: resolve_fd_mode(event.pid, event.fd),
                node_id: Some(request_id),
            }))
        }
        KIND_PIPELINE => {
            let layer = match event.pipeline_layer {
                LAYER_FILESYSTEM => PipelineLayer::Filesystem,
                LAYER_SCSI => PipelineLayer::Scsi,
                LAYER_UFS => PipelineLayer::Ufs,
                android_ebpf_types::LAYER_UIC => PipelineLayer::UicContext,
                LAYER_SCHEDULER => PipelineLayer::SchedulerContext,
                _ => return None,
            };
            let phase = match event.pipeline_phase {
                PHASE_BEGIN => PipelinePhase::Begin,
                PHASE_END => PipelinePhase::End,
                PHASE_INSTANT => PipelinePhase::Instant,
                _ => return None,
            };
            Some(StorageEvent::Pipeline(PipelineObservation {
                ts_ns: event.ts_ns,
                end_ts_ns: None,
                phase,
                layer,
                correlation_id: None,
                stage_key: (event.request_id != 0).then_some(request_id),
                sector: (event.sector != 0).then_some(event.sector),
                bytes: (event.bytes != 0).then_some(event.bytes),
                opcode: (event.reserved & 0b10 != 0).then_some(u32::from(event.operation)),
                status: (event.reserved & 0b1 != 0).then_some(event.status),
                pid: event.pid,
                tid: event.tid,
                name: match layer {
                    PipelineLayer::Filesystem if event.request_id == 0 => "Filesystem context",
                    PipelineLayer::Filesystem => "Filesystem data I/O",
                    PipelineLayer::Scsi => "SCSI command",
                    PipelineLayer::Ufs => "UFS command",
                    PipelineLayer::SchedulerContext => "Scheduler context switch",
                    PipelineLayer::UicContext => "UIC / link context",
                    _ => "Storage stage",
                }
                .into(),
                confidence: if matches!(
                    layer,
                    PipelineLayer::SchedulerContext | PipelineLayer::UicContext
                ) || event.request_id == 0
                {
                    CorrelationConfidence::ContextOnly
                } else if event.correlation_exact != 0 {
                    CorrelationConfidence::Exact
                } else {
                    CorrelationConfidence::Probable
                },
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

fn resolve_fd_identity(pid: u32, fd: i32) -> Option<android_ebpf_protocol::FileIdentity> {
    use std::os::unix::fs::MetadataExt;

    if fd < 0 {
        return None;
    }
    let metadata = fs::metadata(format!("/proc/{pid}/fd/{fd}")).ok()?;
    let device = metadata.dev();
    Some(android_ebpf_protocol::FileIdentity {
        fs_device_major: ((device >> 8) & 0x0fff) as u32,
        fs_device_minor: ((device & 0x00ff) | ((device >> 12) & 0x0fff00)) as u32,
        inode: metadata.ino(),
        inode_generation: None,
        mount_id: resolve_fdinfo_value(pid, fd, "mnt_id", 10),
    })
}

fn resolve_fdinfo_value(pid: u32, fd: i32, key: &str, radix: u32) -> Option<u64> {
    if fd < 0 {
        return None;
    }
    let value = fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}")).ok()?;
    value.lines().find_map(|line| {
        let raw = line.strip_prefix(key)?.strip_prefix(':')?.trim();
        u64::from_str_radix(raw, radix).ok()
    })
}

fn resolve_fd_mode(pid: u32, fd: i32) -> android_ebpf_protocol::FileIoMode {
    let Some(flags) = resolve_fdinfo_value(pid, fd, "flags", 8) else {
        return android_ebpf_protocol::FileIoMode::Unknown;
    };
    const O_DIRECT: u64 = 0o40000;
    const O_SYNC_MASK: u64 = 0o4010000;
    if flags & O_DIRECT != 0 {
        android_ebpf_protocol::FileIoMode::Direct
    } else if flags & O_SYNC_MASK != 0 {
        android_ebpf_protocol::FileIoMode::Sync
    } else {
        android_ebpf_protocol::FileIoMode::Buffered
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

fn emit_diagnostic(
    session_id: &str,
    level: DiagnosticLevel,
    event: &str,
    code: &str,
    outcome: &str,
    detail: Option<String>,
) {
    let rank = match level {
        DiagnosticLevel::Error => 0,
        DiagnosticLevel::Warn => 1,
        DiagnosticLevel::Info => 2,
        DiagnosticLevel::Debug => 3,
        DiagnosticLevel::Trace => 4,
    };
    if rank > LOG_LEVEL.load(Ordering::Relaxed) {
        return;
    }
    let ts_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis() as i64);
    let record = DiagnosticRecord {
        schema_version: SCHEMA_VERSION,
        ts_unix_ms,
        level,
        component: "android-agent".into(),
        event: event.into(),
        session_id: session_id.into(),
        boot_id: read_trimmed("/proc/sys/kernel/random/boot_id").unwrap_or_default(),
        outcome: outcome.into(),
        code: code.into(),
        correlation_id: None,
        node_id: None,
        probe: None,
        duration_ms: None,
        count: None,
        detail,
    }
    .bounded();
    if let Ok(json) = serde_json::to_string(&record) {
        eprintln!("{json}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello_record() -> WireRecord {
        WireRecord::Hello {
            schema_version: SCHEMA_VERSION,
            agent_version: "test".into(),
            boot_id: "boot".into(),
            kernel_release: "kernel".into(),
        }
    }

    #[test]
    fn control_rejects_stale_generation_without_mutating_active_config() {
        let mut active = default_capture_config();
        let expected = active.clone();
        let acknowledgement = apply_control_command(
            &mut active,
            CaptureControlCommand::SetMode {
                generation: 1,
                mode: CaptureMode::Deep,
                reason: "test".into(),
            },
        );

        assert_eq!(acknowledgement.outcome, ControlOutcome::Rejected);
        assert_eq!(active, expected);
    }

    #[test]
    fn bounded_top_reports_eviction_and_keeps_larger_candidate() {
        let mut top = BoundedTop::new(2);
        top.observe("small".into(), 1, 10, None);
        top.observe("medium".into(), 1, 20, None);
        top.observe("large".into(), 1, 30, None);

        let snapshot = top.snapshot(1, HeavyHitterDimension::Process);
        assert_eq!(snapshot.evicted_keys, 1);
        assert_eq!(snapshot.entries.len(), 2);
        assert_eq!(snapshot.entries[0].key, "large");
        assert!(snapshot.entries.iter().all(|entry| entry.key != "small"));
    }

    #[test]
    fn flight_recorder_enforces_time_window_and_byte_capacity() {
        let encoded = serde_json::to_vec(&hello_record()).unwrap().len() + 1;
        let mut recorder = FlightRecorder::new(encoded * 2, 10);
        recorder.observe(0, hello_record());
        recorder.observe(5, hello_record());
        recorder.observe(20, hello_record());

        assert!(recorder.retained_bytes() <= (encoded * 2) as u64);
        assert_eq!(recorder.records.len(), 1);
        assert_eq!(recorder.retained_start(0), 20);
        assert_eq!(recorder.evicted_records, 2);
    }
}
