use std::{
    collections::{BTreeMap, VecDeque},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use android_ebpf_protocol::{
    AccessPattern, AggregateSnapshot, AnalysisEngine, AnalysisSummary, CapabilityState,
    CaptureConfig, CaptureControlCommand, CaptureFilter, CaptureMode, CompletedIo, ControlOutcome,
    CorrelationConfidence, DetailPolicy, DiagnosticLevel, DiagnosticRecord, EdgeConfidence,
    FileOriginView, GraphMetrics, HeavyHitterSnapshot, HistogramMetric, IoNodeKind, IoOperation,
    IoPipeline, IoSizeClass, IoTransactionGraph, PipelineLayer, ProbeCapabilities, SCHEMA_VERSION,
    SegmentRecord, SlowReason, StackFingerprintRecord, TriggerRecord, WireRecord,
};
use crossbeam_channel::{Receiver, Sender, bounded};
use eframe::egui::{self, Color32, RichText, Stroke};
use egui_plot::{Legend, Line, Plot, PlotPoints, Points};

use crate::{
    adb::{AdbClient, AdbDevice, DeviceState, PreflightReport},
    artifacts::{CapturePaths, create_default_session_path},
    capture::{self, CaptureHandle, HostMessage},
    diagnostics::{RotatingJsonl, export_bundle, host_record},
    session::{self, AsyncSessionWriter},
    simulator,
};

const MAX_RECENT: usize = 2_000;
const MAX_EXPLORER_POINTS: usize = 12_000;
const MAX_GRAPH_EXPLORER_POINTS: usize = 2_000;
const MAX_EXPLORER_GROUPS: usize = 32;
const MAX_MESSAGES_PER_FRAME: usize = 1_000;
const LIVE_ANALYSIS_REFRESH: Duration = Duration::from_millis(250);
const BG: Color32 = Color32::from_rgb(12, 17, 27);
const PANEL: Color32 = Color32::from_rgb(20, 27, 40);
const PANEL_RAISED: Color32 = Color32::from_rgb(27, 36, 52);
const BORDER: Color32 = Color32::from_rgb(48, 61, 82);
const TEXT: Color32 = Color32::from_rgb(232, 238, 248);
const MUTED: Color32 = Color32::from_rgb(145, 158, 181);
const ACCENT: Color32 = Color32::from_rgb(74, 144, 245);
const GREEN: Color32 = Color32::from_rgb(63, 201, 145);
const AMBER: Color32 = Color32::from_rgb(245, 181, 65);
const RED: Color32 = Color32::from_rgb(242, 102, 112);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Page {
    Overview,
    Investigate,
    Explore,
    Compare,
    Diagnostics,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExplorerPreset {
    LatencyTimeline,
    LatencyByFile,
    QueuePressure,
    LayerContribution,
    LbaDistribution,
    Custom,
}

impl ExplorerPreset {
    const ALL: [Self; 6] = [
        Self::LatencyTimeline,
        Self::LatencyByFile,
        Self::QueuePressure,
        Self::LayerContribution,
        Self::LbaDistribution,
        Self::Custom,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::LatencyTimeline => "Latency over time",
            Self::LatencyByFile => "Latency by file",
            Self::QueuePressure => "Queue depth vs latency",
            Self::LayerContribution => "Filesystem vs UFS",
            Self::LbaDistribution => "LBA distribution",
            Self::Custom => "Custom",
        }
    }

    fn query(self) -> Option<(AxisMetric, AxisMetric, GroupBy)> {
        match self {
            Self::LatencyTimeline => Some((
                AxisMetric::TimeMs,
                AxisMetric::TotalLatencyMs,
                GroupBy::Direction,
            )),
            Self::LatencyByFile => Some((
                AxisMetric::TimeMs,
                AxisMetric::TotalLatencyMs,
                GroupBy::File,
            )),
            Self::QueuePressure => Some((
                AxisMetric::QueueDepth,
                AxisMetric::TotalLatencyMs,
                GroupBy::Direction,
            )),
            Self::LayerContribution => Some((
                AxisMetric::FilesystemLatencyMs,
                AxisMetric::UfsLatencyMs,
                GroupBy::File,
            )),
            Self::LbaDistribution => {
                Some((AxisMetric::TimeMs, AxisMetric::Sector, GroupBy::Direction))
            }
            Self::Custom => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SetupStep {
    Connect,
    Verify,
    Capture,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AxisMetric {
    TimeMs,
    Sector,
    AddressKiB,
    ChunkKiB,
    TotalLatencyMs,
    QueueLatencyMs,
    DeviceLatencyMs,
    Pid,
    QueueDepth,
    FilesystemLatencyMs,
    UfsLatencyMs,
    CriticalPathMs,
}

impl AxisMetric {
    const ALL: [Self; 12] = [
        Self::TimeMs,
        Self::Sector,
        Self::AddressKiB,
        Self::ChunkKiB,
        Self::TotalLatencyMs,
        Self::QueueLatencyMs,
        Self::DeviceLatencyMs,
        Self::Pid,
        Self::QueueDepth,
        Self::FilesystemLatencyMs,
        Self::UfsLatencyMs,
        Self::CriticalPathMs,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::TimeMs => "Time (ms)",
            Self::Sector => "Sector",
            Self::AddressKiB => "Address (KiB)",
            Self::ChunkKiB => "Chunk (KiB)",
            Self::TotalLatencyMs => "Total latency (ms)",
            Self::QueueLatencyMs => "Queue latency (ms)",
            Self::DeviceLatencyMs => "Device latency (ms)",
            Self::Pid => "PID",
            Self::QueueDepth => "Queue depth",
            Self::FilesystemLatencyMs => "Filesystem latency (ms)",
            Self::UfsLatencyMs => "UFS latency (ms)",
            Self::CriticalPathMs => "Critical path (ms)",
        }
    }

    fn needs_graph(self) -> bool {
        matches!(
            self,
            Self::FilesystemLatencyMs | Self::UfsLatencyMs | Self::CriticalPathMs
        )
    }

    fn value(
        self,
        io: &CompletedIo,
        origin_ns: u64,
        graph: Option<&IoTransactionGraph>,
    ) -> Option<f64> {
        match self {
            Self::TimeMs => Some(io.completion.ts_ns.saturating_sub(origin_ns) as f64 / 1e6),
            Self::Sector => Some(io.issue.sector as f64),
            Self::AddressKiB => Some(io.issue.sector as f64 / 2.0),
            Self::ChunkKiB => Some(io.issue.bytes as f64 / 1024.0),
            Self::TotalLatencyMs => Some(io.total_latency_ns as f64 / 1e6),
            Self::QueueLatencyMs => io.queue_latency_ns.map(|value| value as f64 / 1e6),
            Self::DeviceLatencyMs => Some(io.device_latency_ns as f64 / 1e6),
            Self::Pid => Some(io.issue.pid as f64),
            Self::QueueDepth => Some(io.queue_depth_after as f64),
            Self::FilesystemLatencyMs => {
                graph.and_then(|graph| graph_kind_duration_ms(graph, IoNodeKind::Filesystem))
            }
            Self::UfsLatencyMs => {
                graph.and_then(|graph| graph_kind_duration_ms(graph, IoNodeKind::UfsCommand))
            }
            Self::CriticalPathMs => {
                graph.map(|graph| graph.metrics().critical_path_ns as f64 / 1e6)
            }
        }
    }

    fn requires_graph(self) -> bool {
        matches!(
            self,
            Self::FilesystemLatencyMs | Self::UfsLatencyMs | Self::CriticalPathMs
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GroupBy {
    None,
    Direction,
    AccessPattern,
    SizeClass,
    Process,
    File,
    Origin,
    Confidence,
}

impl GroupBy {
    const ALL: [Self; 8] = [
        Self::None,
        Self::Direction,
        Self::AccessPattern,
        Self::SizeClass,
        Self::Process,
        Self::File,
        Self::Origin,
        Self::Confidence,
    ];
    fn label(self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Direction => "Read / Write",
            Self::AccessPattern => "Sequential / Random",
            Self::SizeClass => "Small / Large",
            Self::Process => "Process",
            Self::File => "File",
            Self::Origin => "Origin",
            Self::Confidence => "Attribution confidence",
        }
    }
    fn needs_graph(self) -> bool {
        matches!(self, Self::File | Self::Origin | Self::Confidence)
    }

    fn key(self, io: &CompletedIo, graph: Option<&IoTransactionGraph>) -> String {
        match self {
            Self::None => "All I/O".into(),
            Self::Direction => operation_label(io.issue.operation).into(),
            Self::AccessPattern => access_label(io.access_pattern).into(),
            Self::SizeClass => size_label(io.size_class).into(),
            Self::Process => format!("{} ({})", io.issue.comm, io.issue.pid),
            Self::File | Self::Origin | Self::Confidence => {
                let Some(graph) = graph else {
                    return "Unattributed".into();
                };
                let Some(request) = graph
                    .nodes
                    .iter()
                    .find(|node| node.kind == IoNodeKind::BlockRequest)
                else {
                    return "Unattributed".into();
                };
                let origins = graph.file_origins_for(request.node_id);
                match self {
                    Self::File => file_group_key(&origins),
                    Self::Origin => {
                        if origins.is_empty() {
                            "Unknown".into()
                        } else if origins.len() > 1 {
                            "Multiple files".into()
                        } else {
                            "File".into()
                        }
                    }
                    Self::Confidence => origins.first().map_or_else(
                        || "Unattributed".into(),
                        |origin| edge_confidence_label(origin.confidence).into(),
                    ),
                    _ => unreachable!(),
                }
            }
        }
    }

    fn requires_graph(self) -> bool {
        matches!(self, Self::File | Self::Origin | Self::Confidence)
    }
}

#[derive(Debug, Clone)]
struct ExplorerView {
    generation: u64,
    x_axis: AxisMetric,
    y_axis: AxisMetric,
    group_by: GroupBy,
    groups: Vec<(String, Vec<[f64; 2]>)>,
    available: usize,
    displayed: usize,
    built_at: Instant,
}

#[derive(Debug, Clone)]
struct PipelineView {
    generation: u64,
    request_id: u64,
    io: CompletedIo,
    pipeline: IoPipeline,
    graph: IoTransactionGraph,
    graph_metrics: GraphMetrics,
    origins: Vec<FileOriginView>,
    slow_reason: Option<SlowReason>,
    built_at: Instant,
}

struct ComparisonBaseline {
    path: PathBuf,
    summary: AnalysisSummary,
    rejected_records: u64,
    capabilities: Option<ProbeCapabilities>,
}

pub struct StudioApp {
    adb: AdbClient,
    tx: Sender<HostMessage>,
    rx: Receiver<HostMessage>,
    devices: Vec<AdbDevice>,
    selected_serial: Option<String>,
    preflight: Option<PreflightReport>,
    status: String,
    diagnostics: VecDeque<DiagnosticRecord>,
    analyzer: AnalysisEngine,
    recent: VecDeque<CompletedIo>,
    capture: Option<CaptureHandle>,
    simulator_stop: Option<Arc<AtomicBool>>,
    writer: Option<AsyncSessionWriter>,
    session_path: Option<PathBuf>,
    session_id: Option<String>,
    log_directory: Option<PathBuf>,
    include_raw_session_in_bundle: bool,
    diagnostic_filter: String,
    capture_log_level: DiagnosticLevel,
    capabilities: Option<ProbeCapabilities>,
    host_diagnostic_writer: Option<RotatingJsonl>,
    received_events: u64,
    rejected_records: u64,
    last_sequence: Option<u64>,
    agent_footer_seen: bool,
    agent_graceful: Option<bool>,
    page: Page,
    x_axis: AxisMetric,
    y_axis: AxisMetric,
    group_by: GroupBy,
    explorer_preset: ExplorerPreset,
    selected_pipeline_request: Option<u64>,
    analysis_generation: u64,
    explorer_view: Option<ExplorerView>,
    pipeline_view: Option<PipelineView>,
    summary_view: Option<(u64, Instant, AnalysisSummary)>,
    comparison: Option<ComparisonBaseline>,
    capture_mode: CaptureMode,
    filter_pid: u32,
    filter_operation: Option<IoOperation>,
    filter_min_bytes: u32,
    slow_threshold_ms: f64,
    control_generation: u64,
    control_status: String,
    latest_aggregate: Option<AggregateSnapshot>,
    heavy_hitters: Vec<HeavyHitterSnapshot>,
    triggers: VecDeque<TriggerRecord>,
    segments: VecDeque<SegmentRecord>,
    stack_fingerprints: VecDeque<StackFingerprintRecord>,
}

impl Default for StudioApp {
    fn default() -> Self {
        let (tx, rx) = bounded(20_000);
        Self {
            adb: AdbClient::default(),
            tx,
            rx,
            devices: Vec::new(),
            selected_serial: None,
            preflight: None,
            status: "Ready".into(),
            diagnostics: VecDeque::new(),
            analyzer: AnalysisEngine::new(),
            recent: VecDeque::new(),
            capture: None,
            simulator_stop: None,
            writer: None,
            session_path: None,
            session_id: None,
            log_directory: None,
            include_raw_session_in_bundle: false,
            diagnostic_filter: String::new(),
            capture_log_level: DiagnosticLevel::Info,
            capabilities: None,
            host_diagnostic_writer: None,
            received_events: 0,
            rejected_records: 0,
            last_sequence: None,
            agent_footer_seen: false,
            agent_graceful: None,
            page: Page::Overview,
            x_axis: AxisMetric::TimeMs,
            y_axis: AxisMetric::TotalLatencyMs,
            group_by: GroupBy::Direction,
            explorer_preset: ExplorerPreset::LatencyTimeline,
            selected_pipeline_request: None,
            analysis_generation: 0,
            explorer_view: None,
            pipeline_view: None,
            summary_view: None,
            comparison: None,
            capture_mode: CaptureMode::Balanced,
            filter_pid: 0,
            filter_operation: None,
            filter_min_bytes: 0,
            slow_threshold_ms: 5.0,
            control_generation: 1,
            control_status: "Balanced · generation 1".into(),
            latest_aggregate: None,
            heavy_hitters: Vec::new(),
            triggers: VecDeque::new(),
            segments: VecDeque::new(),
            stack_fingerprints: VecDeque::new(),
        }
    }
}

impl StudioApp {
    fn is_running(&self) -> bool {
        self.capture.is_some() || self.simulator_stop.is_some()
    }

    fn setup_step(&self) -> SetupStep {
        if self.is_running()
            || self
                .preflight
                .as_ref()
                .is_some_and(PreflightReport::full_ebpf_ready)
        {
            SetupStep::Capture
        } else if self.selected_serial.is_some() {
            SetupStep::Verify
        } else {
            SetupStep::Connect
        }
    }

    fn refresh(&mut self) {
        self.status = "Refreshing ADB devices…".into();
        capture::refresh_devices(self.adb.clone(), self.tx.clone());
    }

    fn preflight(&mut self) {
        if let Some(serial) = self.selected_serial.clone() {
            capture::run_preflight(self.adb.clone(), serial, self.tx.clone());
        }
    }

    fn create_session_at(&mut self, path: PathBuf) -> bool {
        match AsyncSessionWriter::create(&path) {
            Ok(writer) => {
                self.writer = Some(writer);
                self.session_path = Some(path);
                true
            }
            Err(error) => {
                self.push_diagnostic(error.to_string());
                false
            }
        }
    }

    fn start_device(&mut self) {
        let Some(serial) = self.selected_serial.clone() else {
            self.push_diagnostic("Select an authorized device first".into());
            return;
        };
        if !self
            .preflight
            .as_ref()
            .is_some_and(PreflightReport::full_ebpf_ready)
        {
            self.push_diagnostic("Full eBPF preflight has not passed".into());
            return;
        }
        let paths = match CapturePaths::discover() {
            Ok(paths) => paths,
            Err(error) => {
                self.push_diagnostic(error.to_string());
                return;
            }
        };
        self.status = format!("Auto-configured capture → {}", paths.session.display());
        self.session_id = Some(paths.session_id.clone());
        self.log_directory = Some(paths.log_directory.clone());
        let host_writer = match RotatingJsonl::create(paths.host_log.clone()) {
            Ok(writer) => writer,
            Err(error) => {
                self.push_diagnostic(format!("cannot create host diagnostic log: {error}"));
                return;
            }
        };
        self.host_diagnostic_writer = Some(host_writer);
        if !self.create_session_at(paths.session.clone()) {
            self.host_diagnostic_writer = None;
            return;
        }
        self.reset_analysis();
        self.capture = Some(capture::start_adb(
            self.adb.clone(),
            serial,
            paths.agent,
            paths.bpf_object,
            paths.session_id,
            paths.agent_log,
            diagnostic_level_arg(self.capture_log_level).into(),
            self.tx.clone(),
        ));
    }

    fn start_simulator(&mut self) {
        self.session_id = None;
        self.log_directory = None;
        let path = match create_default_session_path() {
            Ok(path) => path,
            Err(error) => {
                self.push_diagnostic(error.to_string());
                return;
            }
        };
        if !self.create_session_at(path) {
            return;
        }
        self.reset_analysis();
        let stop = Arc::new(AtomicBool::new(false));
        simulator::start(self.tx.clone(), stop.clone());
        self.simulator_stop = Some(stop);
    }

    fn stop(&mut self) {
        let mut stopping = false;
        if let Some(handle) = self.capture.take() {
            handle.stop();
            stopping = true;
        }
        if let Some(stop) = self.simulator_stop.take() {
            stop.store(true, Ordering::Release);
            stopping = true;
        }
        if stopping {
            // The reader thread owns stream completion. Keep the writer alive
            // until its Ended message so records already in the pipes are not
            // silently lost during a user-requested stop.
            self.status = "Stopping capture…".into();
        } else {
            self.finish_session();
            self.status = "Stopped".into();
        }
    }

    fn apply_capture_control(&mut self) {
        let Some(handle) = self.capture.clone() else {
            self.push_diagnostic("Start a device capture before applying a live filter".into());
            return;
        };
        let generation = self.control_generation.saturating_add(1);
        let total_latency_ns = (self.slow_threshold_ms.max(0.001) * 1_000_000.0) as u64;
        let config = CaptureConfig {
            generation,
            mode: self.capture_mode,
            filter: CaptureFilter {
                match_all: self.filter_pid == 0
                    && self.filter_operation.is_none()
                    && self.filter_min_bytes == 0,
                pids: (self.filter_pid != 0).then_some(self.filter_pid).into_iter().collect(),
                operations: self.filter_operation.into_iter().collect(),
                min_bytes: (self.filter_min_bytes != 0).then_some(self.filter_min_bytes),
                ..CaptureFilter::default()
            },
            detail: DetailPolicy {
                total_latency_ns,
                ..DetailPolicy::default()
            },
            trigger: Some(android_ebpf_protocol::TriggerPolicy {
                rule: "p99_total_latency".into(),
                threshold: total_latency_ns,
                consecutive_windows: 3,
                deep_duration_ns: 10_000_000_000,
                cooldown_ns: 10_000_000_000,
                arming_timeout_ns: 5_000_000_000,
            }),
        };
        if let Err(error) = config.validate(256) {
            self.push_diagnostic(format!("invalid live capture config: {error}"));
            return;
        }
        match handle.send_control(&CaptureControlCommand::ApplyConfig { config }) {
            Ok(()) => {
                self.control_status = format!("Applying generation {generation}…");
            }
            Err(error) => self.push_diagnostic(error),
        }
    }

    fn finish_session(&mut self) {
        if let Some(writer) = self.writer.take() {
            if let Err(error) = writer.finish(
                self.received_events,
                self.rejected_records,
                self.agent_graceful == Some(true),
            ) {
                self.push_diagnostic(error.to_string());
            }
        }
    }

    fn open_session(&mut self) {
        if self.capture.is_some() || self.simulator_stop.is_some() {
            self.stop();
            self.push_diagnostic_record(host_record(
                self.session_id.as_deref().unwrap_or("session"),
                DiagnosticLevel::Info,
                "session.open",
                "SESSION_OPEN_DEFERRED",
                "waiting",
                Some("capture is stopping; open the session after capture completion".into()),
            ));
            return;
        }
        let Some(path) = rfd::FileDialog::new()
            .add_filter("NDJSON session", &["ndjson"])
            .pick_file()
        else {
            return;
        };
        self.status = "Loading session in background…".into();
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let result = session::load_analysis(&path)
                .map(Box::new)
                .map_err(|error| error.to_string());
            let _ = tx.send(HostMessage::SessionLoaded(path, result));
        });
    }

    fn apply_loaded_session(&mut self, path: PathBuf, loaded: session::LoadedAnalysis) {
        self.recent = loaded
                    .engine
                    .completed_ios()
                    .iter()
                    .rev()
                    .take(MAX_RECENT)
                    .cloned()
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
                self.analyzer = loaded.engine;
                self.analysis_generation = self.analysis_generation.wrapping_add(1);
                self.explorer_view = None;
                self.pipeline_view = None;
                self.summary_view = None;
                self.received_events = loaded.accepted_events;
                self.rejected_records = loaded.rejected_lines;
                self.capabilities = loaded.capabilities;
                self.latest_aggregate = loaded.latest_aggregate;
                self.heavy_hitters = loaded.heavy_hitters;
                self.triggers = loaded.triggers.into_iter().collect();
                self.segments = loaded.segments.into_iter().collect();
                self.stack_fingerprints = loaded.stack_fingerprints.into_iter().collect();
                self.session_path = Some(path);
                self.session_id = None;
                self.log_directory = None;
                self.host_diagnostic_writer = None;
        self.status = match (loaded.integrity_ok, loaded.graceful) {
            (Some(true), Some(true)) => "Offline session loaded · integrity OK".into(),
            (Some(true), _) => "Offline partial session loaded".into(),
            (Some(false), _) => "Offline session loaded · integrity mismatch".into(),
            (None, _) => "Offline legacy/partial session loaded".into(),
        };
    }

    fn open_comparison_session(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("NDJSON session", &["ndjson"])
            .pick_file()
        else {
            return;
        };
        match session::load_analysis(&path) {
            Ok(loaded) => {
                self.comparison = Some(ComparisonBaseline {
                    path,
                    summary: loaded.engine.summary(),
                    rejected_records: loaded.rejected_lines,
                    capabilities: loaded.capabilities,
                });
                self.status = "Comparison baseline loaded".into();
            }
            Err(error) => self.push_diagnostic(format!(
                "cannot load comparison baseline {}: {error}",
                path.display()
            )),
        }
    }

    fn export_csv(&mut self) {
        let Some(session_path) = self.session_path.clone() else {
            self.push_diagnostic("Open or record a session first".into());
            return;
        };
        let Some(path) = rfd::FileDialog::new()
            .add_filter("CSV", &["csv"])
            .set_file_name("android-storage-events.csv")
            .save_file()
        else {
            return;
        };
        self.status = "Exporting CSV in background…".into();
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let result =
                session::export_csv(&session_path, &path).map_err(|error| error.to_string());
            let _ = tx.send(HostMessage::Exported(result));
        });
    }

    fn drain_messages(&mut self) {
        let started = Instant::now();
        for _ in 0..MAX_MESSAGES_PER_FRAME {
            if started.elapsed() >= Duration::from_millis(4) {
                break;
            }
            let Ok(message) = self.rx.try_recv() else {
                break;
            };
            match message {
                HostMessage::Devices(Ok(devices)) => {
                    self.devices = devices;
                    self.selected_serial = self
                        .devices
                        .iter()
                        .find(|device| device.state == DeviceState::Device)
                        .map(|device| device.serial.clone());
                    self.status = format!("{} ADB device(s)", self.devices.len());
                }
                HostMessage::Devices(Err(error)) | HostMessage::Preflight(Err(error)) => {
                    self.push_diagnostic(error)
                }
                HostMessage::Preflight(Ok(report)) => {
                    self.status = if report.full_ebpf_ready() {
                        "Full eBPF preflight passed".into()
                    } else {
                        "Preflight incomplete — see capabilities".into()
                    };
                    self.preflight = Some(report);
                }
                HostMessage::Status(status) => self.status = status,
                HostMessage::Record(record) => self.ingest_record(record),
                HostMessage::Diagnostic(value) => self.push_diagnostic_record(value),
                HostMessage::SessionLoaded(path, Ok(loaded)) => {
                    self.apply_loaded_session(path, *loaded);
                }
                HostMessage::SessionLoaded(_, Err(error)) => self.push_diagnostic(error),
                HostMessage::Exported(Ok(summary)) => {
                    self.status = format!("Exported CSV and {}", summary.display());
                }
                HostMessage::Exported(Err(error)) => self.push_diagnostic(error),
                HostMessage::Ended(result) => {
                    if let Err(error) = result {
                        self.push_diagnostic(error);
                    }
                    if !self.agent_footer_seen {
                        self.push_diagnostic_record(host_record(
                            self.session_id.as_deref().unwrap_or("session"),
                            DiagnosticLevel::Warn,
                            "session.integrity",
                            "SESSION_PARTIAL",
                            "partial",
                            Some(format!(
                                "footer missing; last_sequence={}",
                                self.last_sequence
                                    .map_or_else(|| "none".into(), |value| value.to_string())
                            )),
                        ));
                    }
                    self.finish_session();
                    self.capture = None;
                    self.simulator_stop = None;
                    self.host_diagnostic_writer = None;
                }
            }
        }
    }

    fn ingest_record(&mut self, record: WireRecord) {
        if let WireRecord::Footer { graceful, .. } = &record {
            self.agent_footer_seen = true;
            self.agent_graceful = *graceful;
        }
        if !matches!(&record, WireRecord::Footer { .. })
            && let Some(writer) = self.writer.as_ref()
            && let Err(error) = writer.append(record.clone())
        {
            self.rejected_records += 1;
            self.push_diagnostic(error.to_string());
        }
        match record {
            WireRecord::Event {
                sequence, event, ..
            } => {
                if let Some(previous) = self.last_sequence
                    && sequence != previous.saturating_add(1)
                {
                    self.push_diagnostic_record(host_record(
                        self.session_id.as_deref().unwrap_or("session"),
                        DiagnosticLevel::Warn,
                        "measurement.sequence",
                        "EVENT_SEQUENCE_GAP",
                        "degraded",
                        Some(format!(
                            "expected={} actual={sequence}",
                            previous.saturating_add(1)
                        )),
                    ));
                }
                self.last_sequence = Some(sequence);
                self.received_events += 1;
                if let Some(completed) = self.analyzer.ingest(event) {
                    if self.recent.len() == MAX_RECENT {
                        self.recent.pop_front();
                    }
                    self.recent.push_back(completed);
                }
                self.analysis_generation = self.analysis_generation.wrapping_add(1);
            }
            WireRecord::Health {
                emitted_events,
                kernel_drops,
                userspace_drops,
                correlation_ambiguous,
                correlation_expired,
                key_reused,
                ..
            } => {
                let mut record = host_record(
                    self.session_id.as_deref().unwrap_or("session"),
                    DiagnosticLevel::Info,
                    "capture.health",
                    "CAPTURE_HEALTH",
                    "observed",
                    Some(format!(
                        "emitted={emitted_events} kernel_drops={} userspace_drops={userspace_drops} ambiguous={correlation_ambiguous} expired={correlation_expired} key_reused={key_reused}",
                        kernel_drops
                            .map_or_else(|| "unavailable".into(), |value| value.to_string())
                    )),
                );
                record.count = Some(emitted_events);
                self.push_diagnostic_record(record);
            }
            WireRecord::Capabilities { capabilities, .. } => {
                self.capabilities = Some(capabilities);
            }
            WireRecord::Control {
                acknowledgement, ..
            } => {
                self.control_generation = acknowledgement.active_generation;
                self.control_status = match acknowledgement.outcome {
                    ControlOutcome::Applied => {
                        format!("Applied generation {}", acknowledgement.active_generation)
                    }
                    ControlOutcome::Rejected => format!(
                        "Rejected · {}",
                        acknowledgement.reason.as_deref().unwrap_or("unknown reason")
                    ),
                };
            }
            WireRecord::Aggregate { snapshot, .. } => {
                self.latest_aggregate = Some(snapshot);
            }
            WireRecord::HeavyHitters { snapshot, .. } => {
                self.heavy_hitters
                    .retain(|current| current.dimension != snapshot.dimension);
                self.heavy_hitters.push(snapshot);
            }
            WireRecord::Trigger { trigger, .. } => {
                if self.triggers.len() == 100 {
                    self.triggers.pop_front();
                }
                self.control_status = format!("Adaptive state · {:?}", trigger.to);
                self.triggers.push_back(trigger);
            }
            WireRecord::Segment { segment, .. } => {
                if self.segments.len() == 100 {
                    self.segments.pop_front();
                }
                self.segments.push_back(segment);
            }
            WireRecord::StackFingerprint { fingerprint, .. } => {
                if self.stack_fingerprints.len() == 1_000 {
                    self.stack_fingerprints.pop_front();
                }
                self.stack_fingerprints.push_back(fingerprint);
            }
            _ => {}
        }
    }

    fn reset_analysis(&mut self) {
        self.analyzer = AnalysisEngine::new();
        self.analysis_generation = self.analysis_generation.wrapping_add(1);
        self.explorer_view = None;
        self.pipeline_view = None;
        self.summary_view = None;
        self.recent.clear();
        self.received_events = 0;
        self.rejected_records = 0;
        self.last_sequence = None;
        self.agent_footer_seen = false;
        self.agent_graceful = None;
        self.capabilities = None;
        self.selected_pipeline_request = None;
        self.latest_aggregate = None;
        self.heavy_hitters.clear();
        self.triggers.clear();
        self.segments.clear();
        self.stack_fingerprints.clear();
    }

    fn push_diagnostic(&mut self, value: String) {
        let record = host_record(
            self.session_id.as_deref().unwrap_or("desktop"),
            DiagnosticLevel::Error,
            "desktop.operation",
            "DESKTOP_OPERATION_FAILED",
            "failed",
            Some(value),
        );
        self.push_diagnostic_record(record);
    }

    fn push_diagnostic_record(&mut self, value: DiagnosticRecord) {
        let write_error = self
            .host_diagnostic_writer
            .as_mut()
            .and_then(|writer| writer.append(&value).err());
        if let Some(error) = write_error {
            self.host_diagnostic_writer = None;
            if self.diagnostics.len() == 200 {
                self.diagnostics.pop_front();
            }
            self.diagnostics.push_back(host_record(
                self.session_id.as_deref().unwrap_or("session"),
                DiagnosticLevel::Error,
                "host.diagnostic.write",
                "LOG_WRITE_FAILED",
                "failed",
                Some(error.to_string()),
            ));
        }
        if self.diagnostics.len() == 200 {
            self.diagnostics.pop_front();
        }
        self.diagnostics.push_back(value);
    }

    fn export_diagnostic_bundle(&mut self) {
        let Some(log_directory) = self.log_directory.clone() else {
            self.push_diagnostic("No device-capture diagnostics are available".into());
            return;
        };
        let Some(parent) = rfd::FileDialog::new().pick_folder() else {
            return;
        };
        let destination = parent.join(format!(
            "android-ebpf-diagnostics-{}",
            self.session_id.as_deref().unwrap_or("session")
        ));
        let metadata = serde_json::json!({
            "session_id": self.session_id,
            "capture": {
                "log_level": diagnostic_level_arg(self.capture_log_level),
                "last_sequence": self.last_sequence,
                "agent_footer_seen": self.agent_footer_seen,
                "agent_graceful": self.agent_graceful,
                "received_events": self.received_events,
                "rejected_records": self.rejected_records,
            },
            "device_profile": self.preflight.as_ref().map(|value| serde_json::json!({
                "abi": value.abi,
                "android_version": value.android_version,
                "kernel_release": value.kernel_release,
                "btf": value.btf,
                "tracefs": value.tracefs,
                "root": value.root,
            })),
            "capabilities": self.capabilities,
        });
        match export_bundle(
            &destination,
            &log_directory,
            self.session_path.as_deref(),
            self.include_raw_session_in_bundle,
            Some(&metadata),
        ) {
            Ok(path) => self.status = format!("Diagnostic bundle exported → {}", path.display()),
            Err(error) => self.push_diagnostic(error.to_string()),
        }
    }

    fn analysis_summary(&mut self) -> AnalysisSummary {
        let cache_valid = self
            .summary_view
            .as_ref()
            .is_some_and(|(generation, built_at, _)| {
                *generation == self.analysis_generation
                    || (self.is_running() && built_at.elapsed() < LIVE_ANALYSIS_REFRESH)
            });
        if !cache_valid {
            self.summary_view = Some((
                self.analysis_generation,
                Instant::now(),
                self.analyzer.summary(),
            ));
        }
        self.summary_view
            .as_ref()
            .expect("summary view is rebuilt")
            .2
            .clone()
    }

    fn metrics_ui(&mut self, ui: &mut egui::Ui) {
        let summary = self.analysis_summary();
        let completed = self
            .latest_aggregate
            .as_ref()
            .map_or(summary.completed_ios, |snapshot| snapshot.counters.observed);
        let (bytes_label, bytes_value) = self.latest_aggregate.as_ref().map_or_else(
            || {
                (
                    "READ / WRITE",
                    format!(
                        "{} / {}",
                        format_bytes(summary.read_bytes),
                        format_bytes(summary.write_bytes)
                    ),
                )
            },
            |snapshot| ("TOTAL BYTES", format_bytes(snapshot.counters.bytes)),
        );
        let p50 = self
            .latest_aggregate
            .as_ref()
            .and_then(|snapshot| aggregate_percentile(snapshot, HistogramMetric::TotalLatency, 50))
            .or(summary.p50_latency_ns);
        let p95 = self
            .latest_aggregate
            .as_ref()
            .and_then(|snapshot| aggregate_percentile(snapshot, HistogramMetric::TotalLatency, 95))
            .or(summary.p95_latency_ns);
        let p99 = self
            .latest_aggregate
            .as_ref()
            .and_then(|snapshot| aggregate_percentile(snapshot, HistogramMetric::TotalLatency, 99))
            .or(summary.p99_latency_ns);
        ui.columns(3, |columns| {
            metric_card(
                &mut columns[0],
                "COMPLETED I/O",
                completed.to_string(),
                "requests",
                ACCENT,
            );
            metric_card(
                &mut columns[1],
                bytes_label,
                bytes_value,
                "transferred",
                GREEN,
            );
            metric_card(
                &mut columns[2],
                "P95 LATENCY",
                format_latency(p95),
                if self.latest_aggregate.is_some() {
                    "approximate bucket"
                } else {
                    "end-to-end"
                },
                AMBER,
            );
        });
        ui.add_space(8.0);
        ui.columns(3, |columns| {
            metric_card(
                &mut columns[0],
                "P50 LATENCY",
                format_latency(p50),
                if self.latest_aggregate.is_some() {
                    "approximate bucket"
                } else {
                    "median"
                },
                GREEN,
            );
            metric_card(
                &mut columns[1],
                "P99 LATENCY",
                format_latency(p99),
                if self.latest_aggregate.is_some() {
                    "approximate bucket"
                } else {
                    "tail"
                },
                RED,
            );
            metric_card(
                &mut columns[2],
                "MAX QUEUE DEPTH",
                summary.max_queue_depth.to_string(),
                "in-flight requests",
                ACCENT,
            );
        });
    }

    fn rebuild_explorer_view(&mut self) {
        let samples = self.analyzer.completed_ios();
        let available = samples.len();
        let origin_ns = samples.first().map_or(0, |io| io.completion.ts_ns);
        let needs_graph =
            self.x_axis.needs_graph() || self.y_axis.needs_graph() || self.group_by.needs_graph();
        let limit = if needs_graph {
            MAX_GRAPH_EXPLORER_POINTS
        } else {
            MAX_EXPLORER_POINTS
        };
        let mut groups: BTreeMap<String, Vec<[f64; 2]>> = BTreeMap::new();
        for index in evenly_sample_indices(samples.len(), limit) {
            let io = &samples[index];
            let graph = needs_graph.then(|| self.analyzer.transaction_for(io));
            let graph = graph.as_ref();
            let (Some(x), Some(y)) = (
                self.x_axis.value(io, origin_ns, graph),
                self.y_axis.value(io, origin_ns, graph),
            ) else {
                continue;
            };
            groups
                .entry(self.group_by.key(io, graph))
                .or_default()
                .push([x, y]);
        }
        let displayed = groups.values().map(Vec::len).sum();
        let mut groups: Vec<_> = groups.into_iter().collect();
        if groups.len() > MAX_EXPLORER_GROUPS {
            groups.sort_by(|left, right| right.1.len().cmp(&left.1.len()));
            let overflow = groups.split_off(MAX_EXPLORER_GROUPS - 1);
            let mut other = Vec::new();
            for (_, mut values) in overflow {
                other.append(&mut values);
            }
            groups.push(("Other groups".into(), other));
        }
        groups.sort_by(|left, right| left.0.cmp(&right.0));
        self.explorer_view = Some(ExplorerView {
            generation: self.analysis_generation,
            x_axis: self.x_axis,
            y_axis: self.y_axis,
            group_by: self.group_by,
            groups,
            available,
            displayed,
            built_at: Instant::now(),
        });
    }

    fn rebuild_pipeline_view(&mut self, io: CompletedIo) {
        let pipeline = self.analyzer.pipeline_for(&io);
        let graph = self.analyzer.transaction_for(&io);
        let graph_metrics = graph.metrics();
        let origins = graph
            .nodes
            .iter()
            .find(|node| node.kind == IoNodeKind::BlockRequest)
            .map(|node| graph.file_origins_for(node.node_id))
            .unwrap_or_default();
        let slow_reason = self.analyzer.why_slow(&io);
        self.pipeline_view = Some(PipelineView {
            generation: self.analysis_generation,
            request_id: io.issue.request_id,
            io,
            pipeline,
            graph,
            graph_metrics,
            origins,
            slow_reason,
            built_at: Instant::now(),
        });
    }

    fn explorer_ui(&mut self, ui: &mut egui::Ui) {
        section_header(
            ui,
            "Explore hypotheses",
            "Start with a focused view, then use advanced axes when the question needs it.",
        );
        card_frame().show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("VIEW").size(10.0).strong().color(MUTED));
                let previous = self.explorer_preset;
                egui::ComboBox::from_id_salt("explorer-preset")
                    .selected_text(self.explorer_preset.label())
                    .width(220.0)
                    .show_ui(ui, |ui| {
                        for preset in ExplorerPreset::ALL {
                            ui.selectable_value(&mut self.explorer_preset, preset, preset.label());
                        }
                    });
                if previous != self.explorer_preset
                    && let Some((x, y, group)) = self.explorer_preset.query()
                {
                    self.x_axis = x;
                    self.y_axis = y;
                    self.group_by = group;
                }
                ui.add_space(12.0);
                ui.label(
                    RichText::new("Drag: pan  •  Wheel: zoom  •  Double-click: reset").color(MUTED),
                );
            });
            ui.collapsing("Advanced axes and grouping", |ui| {
                let before = (self.x_axis, self.y_axis, self.group_by);
                ui.horizontal_wrapped(|ui| {
                    axis_combo(ui, "x-axis", "X AXIS", &mut self.x_axis);
                    ui.add_space(8.0);
                    axis_combo(ui, "y-axis", "Y AXIS", &mut self.y_axis);
                    ui.add_space(8.0);
                    ui.vertical(|ui| {
                        ui.label(RichText::new("GROUP BY").size(10.0).color(MUTED));
                        egui::ComboBox::from_id_salt("group-by")
                            .selected_text(self.group_by.label())
                            .width(180.0)
                            .show_ui(ui, |ui| {
                                for group in GroupBy::ALL {
                                    ui.selectable_value(&mut self.group_by, group, group.label());
                                }
                            });
                    });
                });
                if before != (self.x_axis, self.y_axis, self.group_by) {
                    self.explorer_preset = ExplorerPreset::Custom;
                }
            });
        });
        ui.add_space(10.0);

        let cache_valid = self.explorer_view.as_ref().is_some_and(|view| {
            (view.generation == self.analysis_generation
                || (self.is_running() && view.built_at.elapsed() < LIVE_ANALYSIS_REFRESH))
                && view.x_axis == self.x_axis
                && view.y_axis == self.y_axis
                && view.group_by == self.group_by
        });
        if !cache_valid {
            self.rebuild_explorer_view();
        }
        let view = self
            .explorer_view
            .as_ref()
            .expect("explorer view is rebuilt");
        let palette = [
            Color32::LIGHT_BLUE,
            Color32::LIGHT_GREEN,
            Color32::LIGHT_RED,
            Color32::YELLOW,
            Color32::KHAKI,
            Color32::LIGHT_GRAY,
            Color32::from_rgb(200, 120, 255),
            Color32::from_rgb(255, 150, 80),
        ];
        Plot::new("interactive-storage-explorer")
            .height(ui.available_height().max(420.0) - 42.0)
            .x_axis_label(self.x_axis.label())
            .y_axis_label(self.y_axis.label())
            .legend(Legend::default())
            .show(ui, |plot| {
                for (index, (name, values)) in view.groups.iter().enumerate() {
                    let points: PlotPoints = values.iter().copied().collect();
                    plot.points(
                        Points::new(name.clone(), points)
                            .radius(2.5)
                            .color(palette[index % palette.len()]),
                    );
                }
            });
        ui.label(
            RichText::new(format!(
                "Showing {} of {} completed I/O samples{}",
                view.displayed,
                view.available,
                if view.available > view.displayed {
                    " · evenly sampled for interactive rendering"
                } else {
                    ""
                }
            ))
            .small()
            .color(MUTED),
        );
        ui.label(RichText::new("ⓘ Queue latency requires block_rq_insert. Missing values are excluded instead of displayed as zero.").small().color(MUTED));
    }

    fn summary_ui(&mut self, ui: &mut egui::Ui) {
        let summary = self.analysis_summary();
        section_header(
            ui,
            "Overview",
            "What happened, how trustworthy the capture is, and where to investigate next.",
        );
        if let Some(snapshot) = &self.latest_aggregate {
            card_frame().show(ui, |ui| {
                ui.label(
                    RichText::new(format!(
                        "Kernel aggregate · {} observed · {} detailed · {} fast suppressed",
                        snapshot.counters.observed,
                        snapshot.counters.detail_emitted,
                        snapshot.counters.suppressed_fast
                    ))
                    .color(GREEN),
                );
                ui.label(
                    RichText::new(
                        "Top KPIs use approximate histogram buckets; tables below describe retained detail.",
                    )
                    .small()
                    .color(MUTED),
                );
            });
            ui.add_space(10.0);
        }
        ui.columns(4, |columns| {
            summary_card(
                &mut columns[0],
                "Logging time (observed)",
                format_duration(summary.logging_ns),
            );
            summary_card(
                &mut columns[1],
                "Busy time",
                format!(
                    "{} ({:.1}%)",
                    format_duration(summary.busy_ns),
                    ratio(summary.busy_ns, summary.logging_ns)
                ),
            );
            summary_card(
                &mut columns[2],
                "Idle time",
                format!(
                    "{} ({:.1}%)",
                    format_duration(summary.idle_ns),
                    ratio(summary.idle_ns, summary.logging_ns)
                ),
            );
            summary_card(
                &mut columns[3],
                "File attribution",
                format!("{} / {}", summary.attributed_file_ios, summary.file_ios),
            );
        });
        ui.add_space(18.0);
        section_header(
            ui,
            "Session findings",
            "Measured signals only; inferred causes remain in Investigate with confidence evidence.",
        );
        card_frame().show(ui, |ui| {
            if let Some(slowest) = self
                .recent
                .iter()
                .max_by_key(|request| request.total_latency_ns)
                .cloned()
            {
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new("SLOWEST RECENT REQUEST")
                            .size(10.0)
                            .color(MUTED),
                    );
                    ui.label(
                        RichText::new(format!(
                            "#{} · {} · {} · {}",
                            slowest.issue.request_id,
                            operation_label(slowest.issue.operation),
                            format_bytes(slowest.issue.bytes as u64),
                            format_duration(slowest.total_latency_ns)
                        ))
                        .strong(),
                    );
                    if ui.button("Investigate").clicked() {
                        self.selected_pipeline_request = Some(slowest.issue.request_id);
                        self.page = Page::Investigate;
                    }
                });
            } else {
                ui.label(RichText::new("No completed requests yet").color(MUTED));
            }
        });
        ui.add_space(18.0);
        section_header(
            ui,
            "Data quality",
            "Coverage and loss indicators that bound what the analysis can claim.",
        );
        let probe_coverage = self.capabilities.as_ref().map(|capabilities| {
            capabilities.attach_plan.iter().fold(
                (0, 0, 0, 0),
                |(measured, derived, context, unavailable), plan| match plan.state {
                    CapabilityState::Measured => (measured + 1, derived, context, unavailable),
                    CapabilityState::Derived => (measured, derived + 1, context, unavailable),
                    CapabilityState::Context => (measured, derived, context + 1, unavailable),
                    CapabilityState::Unavailable => (measured, derived, context, unavailable + 1),
                },
            )
        });
        let file_coverage = if summary.file_ios == 0 {
            "No file I/O".into()
        } else {
            format!(
                "{:.1}%",
                ratio(summary.attributed_file_ios, summary.file_ios)
            )
        };
        ui.columns(4, |columns| {
            summary_card(
                &mut columns[0],
                "Accepted / rejected",
                format!("{} / {}", self.received_events, self.rejected_records),
            );
            summary_card(&mut columns[1], "File coverage", file_coverage);
            summary_card(
                &mut columns[2],
                "Probe coverage",
                probe_coverage.map_or_else(
                    || "Not reported".into(),
                    |(measured, derived, _, _)| format!("{measured} measured · {derived} derived"),
                ),
            );
            summary_card(
                &mut columns[3],
                "Context / unavailable",
                probe_coverage.map_or_else(
                    || "Not reported".into(),
                    |(_, _, context, unavailable)| format!("{context} / {unavailable}"),
                ),
            );
        });
        ui.add_space(8.0);
        info_banner(
            ui,
            "Missing probes and unattributed requests are excluded or labeled Unavailable; they are never converted to 0 ms.",
        );
        ui.add_space(18.0);
        section_header(
            ui,
            "Block attribution health",
            "Per-request file correlation; ambiguous candidates remain unattributed.",
        );
        ui.columns(4, |columns| {
            summary_card(
                &mut columns[0],
                "Exact",
                summary.attribution.exact.to_string(),
            );
            summary_card(
                &mut columns[1],
                "Probable",
                summary.attribution.probable.to_string(),
            );
            summary_card(
                &mut columns[2],
                "Async probable",
                summary.attribution.probable_async.to_string(),
            );
            summary_card(
                &mut columns[3],
                "Unattributed",
                summary.attribution.unattributed.to_string(),
            );
        });
        ui.add_space(18.0);
        if !self.heavy_hitters.is_empty() {
            section_header(
                ui,
                "Live Top Offenders",
                "Bounded candidates ranked by cumulative latency; coverage and evictions expose approximation limits.",
            );
            ui.columns(self.heavy_hitters.len().min(2), |columns| {
                for (column, snapshot) in columns.iter_mut().zip(&self.heavy_hitters) {
                    card_frame().show(column, |ui| {
                        ui.strong(format!("{:?}", snapshot.dimension));
                        ui.label(
                            RichText::new(format!(
                                "coverage {:.1}% · {} key evictions",
                                ratio(snapshot.covered_metric, snapshot.total_metric),
                                snapshot.evicted_keys
                            ))
                            .small()
                            .color(MUTED),
                        );
                        for entry in snapshot.entries.iter().take(10) {
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(&entry.key)
                                        .monospace()
                                        .color(TEXT),
                                );
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        ui.label(format_duration(entry.cumulative_latency_ns));
                                    },
                                );
                            });
                        }
                    });
                }
            });
            ui.add_space(18.0);
        }
        if !self.triggers.is_empty() || !self.segments.is_empty() || !self.stack_fingerprints.is_empty() {
            section_header(
                ui,
                "Adaptive capture evidence",
                "Trigger transitions, retained flight-recorder windows, and Deep-mode stack cohorts.",
            );
            ui.columns(3, |columns| {
                summary_card(
                    &mut columns[0],
                    "State transitions",
                    self.triggers.len().to_string(),
                );
                summary_card(
                    &mut columns[1],
                    "Retained segments",
                    self.segments.len().to_string(),
                );
                summary_card(
                    &mut columns[2],
                    "Stack cohorts",
                    self.stack_fingerprints.len().to_string(),
                );
            });
            if let Some(segment) = self.segments.back() {
                card_frame().show(ui, |ui| {
                    ui.label(
                        RichText::new(format!(
                            "Latest segment #{} · {} retained · {} evictions",
                            segment.segment_id,
                            format_bytes(segment.retained_bytes),
                            segment.evicted_records
                        ))
                        .color(TEXT),
                    );
                    ui.label(
                        RichText::new(format!(
                            "requested pre-window {} · actual pre-window {}",
                            format_duration(segment.trigger_ts_ns.saturating_sub(segment.requested_start_ts_ns)),
                            format_duration(segment.trigger_ts_ns.saturating_sub(segment.retained_start_ts_ns))
                        ))
                        .small()
                        .color(MUTED),
                    );
                });
            }
            ui.add_space(18.0);
        }
        section_header(
            ui,
            "Workload breakdown",
            "Read/Write × Sequential/Random × Small/Large (32 KiB threshold)",
        );
        card_frame().show(ui, |ui| {
            egui::ScrollArea::vertical()
                .max_height(ui.available_height().max(340.0))
                .show(ui, |ui| {
                    egui::Grid::new("category-summary")
                        .striped(true)
                        .min_col_width(92.0)
                        .spacing([18.0, 10.0])
                        .show(ui, |ui| {
                            for heading in [
                                "Direction",
                                "Access",
                                "Size",
                                "I/O",
                                "Bytes",
                                "Avg chunk",
                                "p50",
                                "p95",
                                "p99",
                            ] {
                                ui.strong(heading);
                            }
                            ui.end_row();
                            for row in &summary.category_summaries {
                                ui.label(operation_label(row.operation));
                                ui.label(access_label(row.access_pattern));
                                ui.label(size_label(row.size_class));
                                ui.label(row.completed_ios.to_string());
                                ui.label(format_bytes(row.bytes));
                                ui.label(format_bytes(row.average_chunk_bytes));
                                ui.label(format_latency(row.p50_latency_ns));
                                ui.label(format_latency(row.p95_latency_ns));
                                ui.label(format_latency(row.p99_latency_ns));
                                ui.end_row();
                            }
                        });
                });
        });
    }

    fn investigate_ui(&mut self, ui: &mut egui::Ui) {
        section_header(
            ui,
            "Investigate one I/O",
            "Select a request, follow its critical path, and inspect file and raw correlation evidence.",
        );
        info_banner(
            ui,
            "Exact = direct request/tag association. Probable = time + LBA/size/thread correlation. UIC is context-only and is never added as command latency.",
        );
        ui.add_space(10.0);

        card_frame().show(ui, |ui| {
            ui.label(
                RichText::new("RECENT REQUESTS")
                    .size(10.0)
                    .strong()
                    .color(MUTED),
            );
            let requests = self.analyzer.completed_ios();
            let row_count = requests.len().min(500);
            let mut selection = self.selected_pipeline_request;
            egui::ScrollArea::vertical()
                .id_salt("investigate-request-list")
                .max_height(190.0)
                .show_rows(ui, 26.0, row_count, |ui, range| {
                    egui::Grid::new("investigate-request-rows")
                        .striped(true)
                        .min_col_width(82.0)
                        .spacing([14.0, 5.0])
                        .show(ui, |ui| {
                            for heading in ["Request", "Op", "Bytes", "Total", "PID", "Process"] {
                                ui.strong(heading);
                            }
                            ui.end_row();
                            for position in range {
                                let request = &requests[requests.len() - 1 - position];
                                if ui
                                    .selectable_label(
                                        selection == Some(request.issue.request_id),
                                        format!("#{}", request.issue.request_id),
                                    )
                                    .clicked()
                                {
                                    selection = Some(request.issue.request_id);
                                }
                                ui.label(operation_label(request.issue.operation));
                                ui.label(format_bytes(request.issue.bytes as u64));
                                ui.label(format_duration(request.total_latency_ns));
                                ui.label(request.issue.pid.to_string());
                                ui.label(&request.issue.comm);
                                ui.end_row();
                            }
                        });
                });
            if requests.len() > row_count {
                ui.label(
                    RichText::new(format!(
                        "Showing the newest {row_count} of {} requests",
                        requests.len()
                    ))
                    .small()
                    .color(MUTED),
                );
            }
            self.selected_pipeline_request = selection;
        });
        ui.add_space(10.0);

        let selected = self
            .selected_pipeline_request
            .and_then(|request_id| {
                self.analyzer
                    .completed_ios()
                    .iter()
                    .rev()
                    .find(|io| io.issue.request_id == request_id)
            })
            .cloned()
            .or_else(|| self.analyzer.completed_ios().last().cloned());
        let Some(io) = selected else {
            card_frame().show(ui, |ui| {
                ui.label(
                    RichText::new("No completed request yet")
                        .strong()
                        .color(TEXT),
                );
                ui.label(
                    RichText::new(
                        "Start the simulator or an eBPF capture to populate the pipeline.",
                    )
                    .color(MUTED),
                );
            });
            return;
        };
        self.selected_pipeline_request = Some(io.issue.request_id);
        let cache_valid = self.pipeline_view.as_ref().is_some_and(|view| {
            (view.generation == self.analysis_generation
                || (self.is_running() && view.built_at.elapsed() < LIVE_ANALYSIS_REFRESH))
                && view.request_id == io.issue.request_id
        });
        if !cache_valid {
            self.rebuild_pipeline_view(io);
        }
        let view = self
            .pipeline_view
            .as_ref()
            .expect("pipeline view is rebuilt")
            .clone();
        let PipelineView {
            io,
            pipeline,
            graph,
            graph_metrics,
            origins,
            slow_reason,
            ..
        } = view;

        card_frame().show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("REQUEST").size(10.0).strong().color(MUTED));
                ui.label(
                    RichText::new(format!(
                        "#{} · {} · {} · sector {}",
                        io.issue.request_id,
                        operation_label(io.issue.operation),
                        format_bytes(io.issue.bytes as u64),
                        io.issue.sector
                    ))
                    .strong(),
                );
                ui.separator();
                ui.label(format!("Total {}", format_duration(pipeline.total_ns())));
                ui.label(
                    RichText::new(format!(
                        "Measured coverage {}",
                        format_duration(pipeline.accounted_ns)
                    ))
                    .color(GREEN),
                );
                ui.label(
                    RichText::new(format!(
                        "Unaccounted {}",
                        format_duration(pipeline.unaccounted_ns)
                    ))
                    .color(if pipeline.unaccounted_ns == 0 {
                        MUTED
                    } else {
                        AMBER
                    }),
                );
                ui.label(format!(
                    "Critical path {}",
                    format_duration(graph_metrics.critical_path_ns)
                ));
                if !graph_metrics.unaccounted.is_empty() {
                    ui.label(
                        RichText::new(format!(
                            "{} unaccounted interval(s): {:?}",
                            graph_metrics.unaccounted.len(),
                            graph_metrics.unaccounted[0].reason
                        ))
                        .color(AMBER),
                    );
                }
            });
        });
        ui.add_space(10.0);
        card_frame().show(ui, |ui| {
            ui.label(
                RichText::new("FILE ORIGIN")
                    .size(10.0)
                    .strong()
                    .color(MUTED),
            );
            if origins.is_empty() {
                ui.label(RichText::new("Unattributed — no unique evidence").color(AMBER));
            } else {
                for origin in &origins {
                    let label = origin
                        .path
                        .as_ref()
                        .and_then(|path| path.path.clone())
                        .unwrap_or_else(|| origin.file.fallback_label());
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new(label).monospace().color(TEXT));
                        status_pill(
                            ui,
                            edge_confidence_label(origin.confidence),
                            match origin.confidence {
                                EdgeConfidence::Exact => GREEN,
                                EdgeConfidence::Probable | EdgeConfidence::ProbableAsync => AMBER,
                                EdgeConfidence::ContextOnly => MUTED,
                            },
                        );
                    });
                }
            }
            if let Some(reason) = slow_reason {
                ui.separator();
                ui.label(RichText::new("WHY SLOW?").size(10.0).strong().color(MUTED));
                ui.label(format!(
                    "{} is {} above the cohort median ({} samples, {}).",
                    reason.stage,
                    format_duration(reason.delta_ns),
                    reason.cohort_samples,
                    edge_confidence_label(reason.confidence)
                ));
            }
        });
        ui.add_space(10.0);

        let origin = pipeline.start_ts_ns;
        card_frame().show(ui, |ui| {
            Plot::new("pipeline-waterfall")
                .height(390.0)
                .x_axis_label("Time from pipeline start (ms)")
                .y_axis_label("Layer (Syscall → UIC)")
                .legend(Legend::default())
                .allow_drag(true)
                .allow_zoom(true)
                .show(ui, |plot| {
                    for span in &pipeline.spans {
                        let x0 = span.start_ts_ns.saturating_sub(origin) as f64 / 1e6;
                        let x1 = span.end_ts_ns.saturating_sub(origin) as f64 / 1e6;
                        let y = pipeline_layer_y(span.layer);
                        let label = format!("{} · {} · {}", pipeline_layer_label(span.layer), confidence_label(span.confidence), span.name);
                        if span.duration_ns() == 0 {
                            plot.points(Points::new(label, PlotPoints::from(vec![[x0, y]])).radius(6.0).color(pipeline_layer_color(span.layer)));
                        } else {
                            plot.line(Line::new(label, PlotPoints::from(vec![[x0, y], [x1, y]])).width(10.0).color(pipeline_layer_color(span.layer)));
                        }
                    }
                });
            ui.label(RichText::new("Drag to pan · wheel to zoom · double-click to reset. Nested bars are not summed; coverage uses interval union.").small().color(MUTED));
        });

        ui.add_space(10.0);
        card_frame().show(ui, |ui| {
            egui::Grid::new("pipeline-detail")
                .striped(true)
                .spacing([18.0, 8.0])
                .show(ui, |ui| {
                    for heading in ["Layer", "Duration", "Confidence", "Source", "Command"] {
                        ui.strong(heading);
                    }
                    ui.end_row();
                    for span in &pipeline.spans {
                        ui.label(pipeline_layer_label(span.layer));
                        ui.label(format_duration(span.duration_ns()));
                        ui.label(confidence_label(span.confidence));
                        ui.label(&span.source);
                        let command = match (span.opcode, span.status) {
                            (Some(opcode), Some(status)) => {
                                format!("opcode 0x{opcode:02x} · status {status}")
                            }
                            (Some(opcode), None) => format!("opcode 0x{opcode:02x}"),
                            (None, Some(status)) => format!("status {status}"),
                            (None, None) => "—".into(),
                        };
                        ui.label(command);
                        ui.end_row();
                    }
                });
        });
        ui.add_space(10.0);
        card_frame().show(ui, |ui| {
            ui.collapsing("Raw block evidence", |ui| {
                egui::Grid::new("investigate-block-evidence")
                    .striped(true)
                    .spacing([18.0, 7.0])
                    .show(ui, |ui| {
                        for (name, value) in [
                            ("Request ID", io.issue.request_id.to_string()),
                            (
                                "Device",
                                format!("{}:{}", io.issue.device_major, io.issue.device_minor),
                            ),
                            ("Sector", io.issue.sector.to_string()),
                            ("Bytes", io.issue.bytes.to_string()),
                            ("PID / TID", format!("{} / {}", io.issue.pid, io.issue.tid)),
                            ("Process", io.issue.comm.clone()),
                            ("Queue latency", format_latency(io.queue_latency_ns)),
                            ("Device latency", format_duration(io.device_latency_ns)),
                            ("Total latency", format_duration(io.total_latency_ns)),
                        ] {
                            ui.label(RichText::new(name).color(MUTED));
                            ui.label(RichText::new(value).monospace());
                            ui.end_row();
                        }
                    });
            });
            ui.separator();
            ui.collapsing(
                format!(
                    "Raw transaction graph · {} nodes / {} edges",
                    graph.nodes.len(),
                    graph.edges.len()
                ),
                |ui| {
                    egui::Grid::new("transaction-graph-nodes")
                        .striped(true)
                        .spacing([14.0, 7.0])
                        .show(ui, |ui| {
                            for heading in [
                                "Node",
                                "Kind",
                                "Duration",
                                "Exclusive",
                                "Origin",
                                "Critical",
                            ] {
                                ui.strong(heading);
                            }
                            ui.end_row();
                            for node in &graph.nodes {
                                ui.label(node.node_id.to_string());
                                ui.label(format!("{:?}", node.kind));
                                ui.label(format_duration(node.duration_ns()));
                                ui.label(format_duration(
                                    graph_metrics
                                        .exclusive_ns
                                        .get(&node.node_id)
                                        .copied()
                                        .unwrap_or(0),
                                ));
                                ui.label(format!("{:?}", node.origin));
                                ui.label(if graph_metrics.critical_path.contains(&node.node_id) {
                                    "●"
                                } else {
                                    ""
                                });
                                ui.end_row();
                            }
                        });
                    ui.separator();
                    for edge in &graph.edges {
                        ui.label(format!(
                            "{} → {} · {:?} · {} · evidence {}",
                            edge.from_node_id,
                            edge.to_node_id,
                            edge.relation,
                            edge_confidence_label(edge.confidence),
                            edge.evidence.len()
                        ));
                    }
                },
            );
        });
        ui.add_space(10.0);
        ui.collapsing("Recent raw session evidence", |ui| {
            self.table_ui(ui);
            ui.add_space(10.0);
            self.files_ui(ui);
        });
    }

    fn files_ui(&self, ui: &mut egui::Ui) {
        section_header(
            ui,
            "File I/O attribution",
            "Which process and file descriptor initiated a read or write syscall.",
        );
        info_banner(
            ui,
            "File paths are resolved from /proc/<pid>/fd/<fd> at syscall time. Buffered writeback cannot be claimed as exact block-request correlation.",
        );
        ui.add_space(10.0);
        card_frame().show(ui, |ui| {
            egui::Grid::new("file-ios-header")
                .spacing([16.0, 9.0])
                .show(ui, |ui| {
                    for heading in [
                        "End ns",
                        "Op",
                        "Requested",
                        "Completed",
                        "Latency",
                        "PID",
                        "FD",
                        "Confidence",
                        "Identity",
                        "Path snapshot",
                    ] {
                        ui.strong(heading);
                    }
                    ui.end_row();
                });
            let files = self.analyzer.file_ios();
            let row_count = files.len().min(1_000);
            egui::ScrollArea::vertical().show_rows(ui, 27.0, row_count, |ui, range| {
                egui::Grid::new("file-ios-rows")
                    .striped(true)
                    .spacing([16.0, 9.0])
                    .show(ui, |ui| {
                        for position in range {
                            let file = &files[files.len() - 1 - position];
                            ui.label(file.end_ts_ns.to_string());
                            ui.label(operation_label(file.operation));
                            ui.label(format_bytes(file.requested_bytes));
                            ui.label(file.completed_bytes.to_string());
                            ui.label(format_duration(
                                file.end_ts_ns.saturating_sub(file.start_ts_ns),
                            ));
                            ui.label(file.pid.to_string());
                            ui.label(file.fd.to_string());
                            ui.label(format!("{:?}", file.confidence));
                            ui.label(file.file_identity.as_ref().map_or_else(
                                || "<unknown>".into(),
                                |identity| identity.fallback_label(),
                            ));
                            ui.label(
                                file.path_snapshot
                                    .as_ref()
                                    .and_then(|snapshot| snapshot.path.as_deref())
                                    .or(file.path.as_deref())
                                    .unwrap_or("<unresolved>"),
                            );
                            ui.end_row();
                        }
                    });
            });
        });
    }

    fn table_ui(&self, ui: &mut egui::Ui) {
        section_header(
            ui,
            "Completed block I/O",
            "Newest completed requests from the current or loaded session.",
        );
        card_frame().show(ui, |ui| {
            egui::ScrollArea::vertical()
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    egui::Grid::new("recent-ios")
                        .striped(true)
                        .spacing([15.0, 9.0])
                        .show(ui, |ui| {
                            for heading in [
                                "Time ns",
                                "Op",
                                "Access",
                                "Size",
                                "Bytes",
                                "Sector",
                                "Queue",
                                "Device",
                                "Total",
                                "File / Origin",
                                "PID",
                                "Comm",
                            ] {
                                ui.strong(heading);
                            }
                            ui.end_row();
                            for io in self.recent.iter().rev().take(200) {
                                ui.label(io.completion.ts_ns.to_string());
                                ui.label(format!("{:?}", io.issue.operation));
                                ui.label(access_label(io.access_pattern));
                                ui.label(size_label(io.size_class));
                                ui.label(io.issue.bytes.to_string());
                                ui.label(io.issue.sector.to_string());
                                ui.label(format_latency(io.queue_latency_ns));
                                ui.label(format_latency(Some(io.device_latency_ns)));
                                ui.label(format_latency(Some(io.total_latency_ns)));
                                let graph = self.analyzer.transaction_for(io);
                                let origins = graph
                                    .nodes
                                    .iter()
                                    .find(|node| node.kind == IoNodeKind::BlockRequest)
                                    .map(|node| graph.file_origins_for(node.node_id))
                                    .unwrap_or_default();
                                ui.label(if origins.is_empty() {
                                    "Unattributed".into()
                                } else if origins.len() > 1 {
                                    format!("{} files", origins.len())
                                } else {
                                    origins[0]
                                        .path
                                        .as_ref()
                                        .and_then(|path| path.path.clone())
                                        .unwrap_or_else(|| origins[0].file.fallback_label())
                                });
                                ui.label(io.issue.pid.to_string());
                                ui.label(&io.issue.comm);
                                ui.end_row();
                            }
                        });
                });
        });
    }

    fn compare_ui(&mut self, ui: &mut egui::Ui) {
        section_header(
            ui,
            "Compare sessions",
            "Measure the current capture against a separately loaded baseline without replacing it.",
        );
        card_frame().show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                if ui.button("Open baseline session").clicked() {
                    self.open_comparison_session();
                }
                if self.comparison.is_some() && ui.button("Clear baseline").clicked() {
                    self.comparison = None;
                }
                ui.label(
                    RichText::new("Delta = Current − Baseline; lower latency is normally better.")
                        .color(MUTED),
                );
            });
        });
        ui.add_space(10.0);

        let Some(baseline) = self.comparison.as_ref() else {
            card_frame().show(ui, |ui| {
                ui.label(RichText::new("No baseline loaded").strong());
                ui.label(
                    RichText::new(
                        "Open an earlier NDJSON session to compare workload, latency, queue pressure, and attribution.",
                    )
                    .color(MUTED),
                );
            });
            return;
        };
        let baseline_summary = baseline.summary.clone();
        let baseline_name = baseline
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("baseline.ndjson")
            .to_owned();
        let baseline_rejected = baseline.rejected_records;
        let baseline_probe_count = baseline
            .capabilities
            .as_ref()
            .map_or(0, |capabilities| capabilities.attach_plan.len());
        let current = self.analysis_summary();

        if baseline_summary.completed_ios == 0 && baseline_summary.file_ios == 0 {
            card_frame().show(ui, |ui| {
                ui.label(RichText::new("Baseline has no analyzable I/O").strong());
                ui.label(
                    RichText::new(
                        "Choose a session containing completed block or file I/O events.",
                    )
                    .color(MUTED),
                );
            });
            return;
        }
        if current.completed_ios == 0 && current.file_ios == 0 {
            card_frame().show(ui, |ui| {
                ui.label(RichText::new("Current session has no analyzable I/O").strong());
                ui.label(
                    RichText::new("Open or record the current session before calculating deltas.")
                        .color(MUTED),
                );
            });
            return;
        }

        info_banner(
            ui,
            &format!(
                "Baseline: {baseline_name} · {} rejected record(s) · {} declared probe(s)",
                baseline_rejected, baseline_probe_count
            ),
        );
        ui.add_space(10.0);
        card_frame().show(ui, |ui| {
            egui::Grid::new("session-comparison")
                .striped(true)
                .min_col_width(120.0)
                .spacing([22.0, 10.0])
                .show(ui, |ui| {
                    for heading in ["Metric", "Baseline", "Current", "Delta"] {
                        ui.strong(heading);
                    }
                    ui.end_row();
                    comparison_row(
                        ui,
                        "Completed I/O",
                        baseline_summary.completed_ios,
                        current.completed_ios,
                        |value| value.to_string(),
                    );
                    comparison_row(
                        ui,
                        "Read bytes",
                        baseline_summary.read_bytes,
                        current.read_bytes,
                        format_bytes,
                    );
                    comparison_row(
                        ui,
                        "Write bytes",
                        baseline_summary.write_bytes,
                        current.write_bytes,
                        format_bytes,
                    );
                    comparison_optional_latency_row(
                        ui,
                        "p50 latency",
                        baseline_summary.p50_latency_ns,
                        current.p50_latency_ns,
                    );
                    comparison_optional_latency_row(
                        ui,
                        "p95 latency",
                        baseline_summary.p95_latency_ns,
                        current.p95_latency_ns,
                    );
                    comparison_optional_latency_row(
                        ui,
                        "p99 latency",
                        baseline_summary.p99_latency_ns,
                        current.p99_latency_ns,
                    );
                    comparison_row(
                        ui,
                        "Max queue depth",
                        baseline_summary.max_queue_depth as u64,
                        current.max_queue_depth as u64,
                        |value| value.to_string(),
                    );
                    comparison_ratio_row(
                        ui,
                        "File attribution",
                        ratio(
                            baseline_summary.attributed_file_ios,
                            baseline_summary.file_ios,
                        ),
                        ratio(current.attributed_file_ios, current.file_ios),
                    );
                });
        });
    }

    fn diagnostics_ui(&mut self, ui: &mut egui::Ui) {
        section_header(
            ui,
            "Structured diagnostics",
            "Capture, probe, decode and correlation records for the current session.",
        );
        card_frame().show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label("Filter");
                ui.text_edit_singleline(&mut self.diagnostic_filter);
                ui.checkbox(
                    &mut self.include_raw_session_in_bundle,
                    "Include raw session in bundle",
                );
                if ui
                    .add_enabled(
                        self.log_directory.is_some(),
                        egui::Button::new("Export diagnostic bundle"),
                    )
                    .clicked()
                {
                    self.export_diagnostic_bundle();
                }
            });
        });
        if let Some(capabilities) = &self.capabilities {
            ui.add_space(10.0);
            card_frame().show(ui, |ui| {
                ui.label(
                    RichText::new("PROBE STATUS")
                        .size(10.0)
                        .strong()
                        .color(MUTED),
                );
                egui::Grid::new("probe-status")
                    .striped(true)
                    .spacing([14.0, 7.0])
                    .show(ui, |ui| {
                        for heading in ["Layer", "Probe", "State", "Format", "Reason"] {
                            ui.strong(heading);
                        }
                        ui.end_row();
                        for plan in &capabilities.attach_plan {
                            ui.label(pipeline_layer_label(plan.layer));
                            ui.label(format!("{}/{}", plan.group, plan.event_or_function));
                            ui.label(format!("{:?}", plan.state));
                            ui.label(plan.format_hash.as_deref().unwrap_or("—"));
                            ui.label(plan.reason.as_deref().unwrap_or(""));
                            ui.end_row();
                        }
                    });
            });
        }
        ui.add_space(10.0);
        let filter = self.diagnostic_filter.to_ascii_lowercase();
        card_frame().show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                egui::Grid::new("structured-diagnostics")
                    .striped(true)
                    .spacing([14.0, 8.0])
                    .show(ui, |ui| {
                        for heading in [
                            "Time",
                            "Level",
                            "Component",
                            "Code",
                            "Event",
                            "Outcome",
                            "Detail",
                        ] {
                            ui.strong(heading);
                        }
                        ui.end_row();
                        for record in self.diagnostics.iter().rev().filter(|record| {
                            filter.is_empty()
                                || record.component.to_ascii_lowercase().contains(&filter)
                                || record.code.to_ascii_lowercase().contains(&filter)
                                || record.event.to_ascii_lowercase().contains(&filter)
                                || record
                                    .correlation_id
                                    .is_some_and(|id| id.to_string().contains(&filter))
                        }) {
                            ui.label(record.ts_unix_ms.to_string());
                            ui.label(format!("{:?}", record.level));
                            ui.label(&record.component);
                            ui.label(&record.code);
                            ui.label(&record.event);
                            ui.label(&record.outcome);
                            ui.label(record.detail.as_deref().unwrap_or(""));
                            ui.end_row();
                        }
                    });
            });
        });
    }
}

impl eframe::App for StudioApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.drain_messages();
        if self.is_running() || !self.rx.is_empty() {
            ui.ctx().request_repaint_after(Duration::from_millis(33));
        }
        apply_theme(ui.ctx());

        egui::Panel::top("app-header")
            .frame(
                egui::Frame::new()
                    .fill(PANEL)
                    .inner_margin(egui::Margin::symmetric(22, 14))
                    .stroke(Stroke::new(1.0, BORDER)),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("◈").size(26.0).color(ACCENT));
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new("ANDROID eBPF STUDIO")
                                .size(18.0)
                                .strong()
                                .color(TEXT),
                        );
                        ui.label(
                            RichText::new("Storage observability workspace")
                                .size(11.0)
                                .color(MUTED),
                        );
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        status_pill(
                            ui,
                            &self.status,
                            if self.is_running() { GREEN } else { ACCENT },
                        );
                        if ui
                            .add_enabled(
                                self.session_path.is_some(),
                                egui::Button::new("Export CSV"),
                            )
                            .clicked()
                        {
                            self.export_csv();
                        }
                        if ui.button("Open session").clicked() {
                            self.open_session();
                        }
                    });
                });
            });

        egui::Panel::left("navigation")
            .exact_size(244.0)
            .resizable(false)
            .frame(
                egui::Frame::new()
                    .fill(PANEL)
                    .inner_margin(egui::Margin::same(16))
                    .stroke(Stroke::new(1.0, BORDER)),
            )
            .show(ui, |ui| {
                ui.label(RichText::new("WORKFLOW").size(10.0).strong().color(MUTED));
                ui.add_space(10.0);
                workflow_step(
                    ui,
                    1,
                    "Connect device",
                    self.setup_step() == SetupStep::Connect,
                    self.selected_serial.is_some(),
                );
                workflow_step(
                    ui,
                    2,
                    "Verify capabilities",
                    self.setup_step() == SetupStep::Verify,
                    self.preflight
                        .as_ref()
                        .is_some_and(PreflightReport::full_ebpf_ready),
                );
                workflow_step(
                    ui,
                    3,
                    "Capture & analyze",
                    self.setup_step() == SetupStep::Capture,
                    self.is_running(),
                );
                ui.add_space(18.0);

                ui.label(
                    RichText::new("TARGET DEVICE")
                        .size(10.0)
                        .strong()
                        .color(MUTED),
                );
                ui.add_space(7.0);
                egui::ComboBox::from_id_salt("device")
                    .selected_text(
                        self.selected_serial
                            .as_deref()
                            .unwrap_or("No device selected"),
                    )
                    .width(210.0)
                    .show_ui(ui, |ui| {
                        for device in &self.devices {
                            ui.selectable_value(
                                &mut self.selected_serial,
                                Some(device.serial.clone()),
                                format!(
                                    "{} · {}",
                                    device.model.as_deref().unwrap_or("Android"),
                                    device.serial
                                ),
                            );
                        }
                    });
                ui.add_space(8.0);
                if ui
                    .add_sized([210.0, 34.0], egui::Button::new("↻  Refresh ADB devices"))
                    .clicked()
                {
                    self.refresh();
                }
                if ui
                    .add_enabled(
                        self.selected_serial.is_some(),
                        egui::Button::new("✓  Run preflight").min_size(egui::vec2(210.0, 34.0)),
                    )
                    .clicked()
                {
                    self.preflight();
                }
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new("LOG LEVEL").size(10.0).color(MUTED));
                    egui::ComboBox::from_id_salt("capture-log-level")
                        .selected_text(diagnostic_level_arg(self.capture_log_level))
                        .show_ui(ui, |ui| {
                            for level in [
                                DiagnosticLevel::Info,
                                DiagnosticLevel::Debug,
                                DiagnosticLevel::Trace,
                            ] {
                                ui.selectable_value(
                                    &mut self.capture_log_level,
                                    level,
                                    diagnostic_level_arg(level),
                                );
                            }
                        });
                });
                ui.add_space(6.0);
                ui.collapsing("LIVE FILTER & MODE", |ui| {
                    egui::ComboBox::from_id_salt("capture-mode")
                        .selected_text(capture_mode_label(self.capture_mode))
                        .width(190.0)
                        .show_ui(ui, |ui| {
                            for mode in [
                                CaptureMode::Basic,
                                CaptureMode::Balanced,
                                CaptureMode::Deep,
                                CaptureMode::RawAll,
                            ] {
                                ui.selectable_value(
                                    &mut self.capture_mode,
                                    mode,
                                    capture_mode_label(mode),
                                );
                            }
                        });
                    ui.horizontal(|ui| {
                        ui.label("PID (0 = all)");
                        ui.add(egui::DragValue::new(&mut self.filter_pid).range(0..=u32::MAX));
                    });
                    egui::ComboBox::from_id_salt("filter-operation")
                        .selected_text(
                            self.filter_operation
                                .map_or("All operations".into(), |value| format!("{value:?}")),
                        )
                        .width(190.0)
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut self.filter_operation,
                                None,
                                "All operations",
                            );
                            for operation in [IoOperation::Read, IoOperation::Write] {
                                ui.selectable_value(
                                    &mut self.filter_operation,
                                    Some(operation),
                                    format!("{operation:?}"),
                                );
                            }
                        });
                    ui.horizontal(|ui| {
                        ui.label("Min bytes");
                        ui.add(
                            egui::DragValue::new(&mut self.filter_min_bytes)
                                .range(0..=u32::MAX),
                        );
                    });
                    ui.horizontal(|ui| {
                        ui.label("Slow I/O ms");
                        ui.add(
                            egui::DragValue::new(&mut self.slow_threshold_ms)
                                .speed(0.1)
                                .range(0.001..=60_000.0),
                        );
                    });
                    if ui
                        .add_enabled(
                            self.capture.is_some(),
                            egui::Button::new("Apply live config")
                                .min_size(egui::vec2(190.0, 30.0)),
                        )
                        .clicked()
                    {
                        self.apply_capture_control();
                    }
                    ui.label(
                        RichText::new(&self.control_status)
                            .size(10.0)
                            .color(MUTED),
                    );
                    if self.capture_mode == CaptureMode::RawAll {
                        ui.label(
                            RichText::new("RawAll can generate high event and UI load")
                                .size(10.0)
                                .color(AMBER),
                        );
                    }
                });
                let can_start = self
                    .preflight
                    .as_ref()
                    .is_some_and(PreflightReport::full_ebpf_ready)
                    && !self.is_running();
                if ui
                    .add_enabled(
                        can_start,
                        egui::Button::new(RichText::new("▶  Start eBPF capture").color(TEXT))
                            .fill(ACCENT)
                            .min_size(egui::vec2(210.0, 38.0)),
                    )
                    .clicked()
                {
                    self.start_device();
                }
                if ui
                    .add_enabled(
                        !self.is_running(),
                        egui::Button::new("Run simulator").min_size(egui::vec2(210.0, 32.0)),
                    )
                    .clicked()
                {
                    self.start_simulator();
                }
                if ui
                    .add_enabled(
                        self.is_running(),
                        egui::Button::new(RichText::new("■  Stop capture").color(RED))
                            .min_size(egui::vec2(210.0, 34.0)),
                    )
                    .clicked()
                {
                    self.stop();
                }

                ui.add_space(20.0);
                ui.separator();
                ui.add_space(12.0);
                ui.label(RichText::new("ANALYSIS").size(10.0).strong().color(MUTED));
                ui.add_space(6.0);
                nav_item(
                    ui,
                    &mut self.page,
                    Page::Overview,
                    "▦",
                    "Overview",
                    "Findings and data quality",
                );
                nav_item(
                    ui,
                    &mut self.page,
                    Page::Investigate,
                    "⇢",
                    "Investigate",
                    "Request, file and pipeline",
                );
                nav_item(
                    ui,
                    &mut self.page,
                    Page::Explore,
                    "⌁",
                    "Explore",
                    "Presets, axes and groups",
                );
                nav_item(
                    ui,
                    &mut self.page,
                    Page::Compare,
                    "⇄",
                    "Compare",
                    "Baseline vs current",
                );
                ui.add_space(12.0);
                ui.label(RichText::new("OPERATIONS").size(10.0).strong().color(MUTED));
                ui.add_space(4.0);
                nav_item(
                    ui,
                    &mut self.page,
                    Page::Diagnostics,
                    "⚙",
                    "Diagnostics",
                    "Probe and correlation logs",
                );

                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    ui.label(
                        RichText::new(format!(
                            "{} received  •  {} rejected",
                            self.received_events, self.rejected_records
                        ))
                        .size(10.0)
                        .color(MUTED),
                    );
                    if let Some(path) = &self.session_path {
                        ui.label(
                            RichText::new(
                                path.file_name()
                                    .and_then(|v| v.to_str())
                                    .unwrap_or("session.ndjson"),
                            )
                            .size(10.0)
                            .color(MUTED),
                        );
                    }
                });
            });

        egui::Panel::bottom("diagnostics")
            .frame(
                egui::Frame::new()
                    .fill(PANEL)
                    .inner_margin(egui::Margin::symmetric(18, 8))
                    .stroke(Stroke::new(1.0, BORDER)),
            )
            .show(ui, |ui| {
                ui.collapsing(format!("Diagnostics  ({})", self.diagnostics.len()), |ui| {
                    egui::ScrollArea::vertical()
                        .max_height(110.0)
                        .show(ui, |ui| {
                            for value in self.diagnostics.iter().rev() {
                                ui.label(
                                    RichText::new(format!(
                                        "{:?} {} {} {}",
                                        value.level,
                                        value.component,
                                        value.code,
                                        value.detail.as_deref().unwrap_or("")
                                    ))
                                    .monospace()
                                    .size(10.0)
                                    .color(
                                        match value.level {
                                            DiagnosticLevel::Error => RED,
                                            DiagnosticLevel::Warn => AMBER,
                                            _ => MUTED,
                                        },
                                    ),
                                );
                            }
                        });
                });
            });

        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(BG)
                    .inner_margin(egui::Margin::same(22)),
            )
            .show(ui, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    if self.page == Page::Overview {
                        self.metrics_ui(ui);
                        ui.add_space(20.0);
                    }
                    match self.page {
                        Page::Overview => self.summary_ui(ui),
                        Page::Investigate => self.investigate_ui(ui),
                        Page::Explore => self.explorer_ui(ui),
                        Page::Compare => self.compare_ui(ui),
                        Page::Diagnostics => self.diagnostics_ui(ui),
                    }
                    if let Some(report) = &self.preflight {
                        ui.add_space(14.0);
                        capability_panel(ui, report);
                    }
                });
            });
    }
}

fn capture_mode_label(mode: CaptureMode) -> &'static str {
    match mode {
        CaptureMode::Basic => "Basic · aggregates only",
        CaptureMode::Balanced => "Balanced · tail + sample",
        CaptureMode::Deep => "Deep · pipeline/context",
        CaptureMode::RawAll => "RawAll · every event",
    }
}

fn aggregate_percentile(
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

fn apply_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = BG;
    visuals.window_fill = PANEL;
    visuals.extreme_bg_color = Color32::from_rgb(9, 13, 21);
    visuals.faint_bg_color = Color32::from_rgb(24, 32, 47);
    visuals.selection.bg_fill = ACCENT;
    visuals.widgets.inactive.bg_fill = PANEL_RAISED;
    visuals.widgets.inactive.weak_bg_fill = PANEL_RAISED;
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT);
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(38, 51, 73);
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, Color32::WHITE);
    visuals.widgets.active.bg_fill = ACCENT;
    ctx.set_visuals(visuals);
    ctx.global_style_mut(|style| {
        style.spacing.item_spacing = egui::vec2(8.0, 8.0);
        style.spacing.button_padding = egui::vec2(12.0, 7.0);
    });
}

fn card_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(PANEL)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(10)
        .inner_margin(egui::Margin::same(16))
}

fn section_header(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    ui.label(RichText::new(title).size(20.0).strong().color(TEXT));
    ui.label(RichText::new(subtitle).size(11.0).color(MUTED));
    ui.add_space(10.0);
}

fn metric_card(ui: &mut egui::Ui, label: &str, value: String, hint: &str, color: Color32) {
    card_frame().show(ui, |ui| {
        ui.label(RichText::new(label).size(10.0).strong().color(MUTED));
        ui.add_space(5.0);
        ui.label(RichText::new(value).size(22.0).strong().color(color));
        ui.label(RichText::new(hint).size(10.0).color(MUTED));
    });
}

fn status_pill(ui: &mut egui::Ui, text: &str, color: Color32) {
    egui::Frame::new()
        .fill(Color32::from_rgba_unmultiplied(
            color.r(),
            color.g(),
            color.b(),
            32,
        ))
        .stroke(Stroke::new(1.0, color))
        .corner_radius(12)
        .inner_margin(egui::Margin::symmetric(10, 5))
        .show(ui, |ui| {
            ui.label(RichText::new(format!("●  {text}")).size(11.0).color(color));
        });
}

fn workflow_step(ui: &mut egui::Ui, number: usize, label: &str, active: bool, done: bool) {
    let color = if done {
        GREEN
    } else if active {
        ACCENT
    } else {
        MUTED
    };
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(if done {
                "✓".into()
            } else {
                number.to_string()
            })
            .strong()
            .color(color),
        );
        ui.label(
            RichText::new(label)
                .strong()
                .color(if active || done { TEXT } else { MUTED }),
        );
    });
}

fn nav_item(
    ui: &mut egui::Ui,
    page: &mut Page,
    value: Page,
    icon: &str,
    title: &str,
    detail: &str,
) {
    let selected = *page == value;
    let response = egui::Frame::new()
        .fill(if selected {
            Color32::from_rgb(32, 57, 91)
        } else {
            Color32::TRANSPARENT
        })
        .corner_radius(7)
        .inner_margin(egui::Margin::symmetric(10, 8))
        .show(ui, |ui| {
            ui.set_min_width(190.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new(icon).size(18.0).color(if selected {
                    ACCENT
                } else {
                    MUTED
                }));
                ui.vertical(|ui| {
                    ui.label(RichText::new(title).strong().color(if selected {
                        TEXT
                    } else {
                        MUTED
                    }));
                    ui.label(RichText::new(detail).size(9.0).color(MUTED));
                });
            });
        })
        .response
        .interact(egui::Sense::click());
    if response.clicked() {
        *page = value;
    }
}

fn info_banner(ui: &mut egui::Ui, text: &str) {
    egui::Frame::new()
        .fill(Color32::from_rgb(24, 43, 67))
        .stroke(Stroke::new(1.0, ACCENT))
        .corner_radius(6)
        .inner_margin(egui::Margin::same(10))
        .show(ui, |ui| {
            ui.label(
                RichText::new(format!("ⓘ  {text}"))
                    .size(11.0)
                    .color(Color32::from_rgb(174, 205, 248)),
            );
        });
}

fn capability_panel(ui: &mut egui::Ui, report: &PreflightReport) {
    ui.collapsing("Device capabilities", |ui| {
        ui.horizontal_wrapped(|ui| {
            capability_badge(ui, "Root", report.root);
            capability_badge(ui, "BTF", report.btf);
            capability_badge(ui, "TraceFS", report.tracefs);
            capability_badge(ui, "Insert", report.block_insert);
            capability_badge(ui, "Issue", report.block_issue);
            capability_badge(ui, "Complete", report.block_complete);
            capability_badge(ui, "File syscalls", report.raw_syscalls);
        });
        ui.label(
            RichText::new(format!(
                "{}  •  Android {}  •  Kernel {}  •  UFS {}  •  SCSI {}  •  FS {} event path(s)",
                report.abi,
                report.android_version,
                report.kernel_release,
                report.ufs_events.len(),
                report.scsi_events.len(),
                report.fs_events.len()
            ))
            .size(10.0)
            .color(MUTED),
        );
    });
}

fn capability_badge(ui: &mut egui::Ui, label: &str, available: bool) {
    let color = if available { GREEN } else { RED };
    ui.label(RichText::new(format!("{} {label}", if available { "✓" } else { "×" })).color(color));
}

fn format_latency(value: Option<u64>) -> String {
    match value {
        Some(ns) if ns >= 1_000_000 => format!("{:.2} ms", ns as f64 / 1_000_000.0),
        Some(ns) if ns >= 1_000 => format!("{:.1} µs", ns as f64 / 1_000.0),
        Some(ns) => format!("{ns} ns"),
        None => "—".into(),
    }
}

fn format_duration(ns: u64) -> String {
    if ns >= 1_000_000_000 {
        format!("{:.3} s", ns as f64 / 1e9)
    } else if ns >= 1_000_000 {
        format!("{:.3} ms", ns as f64 / 1e6)
    } else if ns >= 1_000 {
        format!("{:.1} µs", ns as f64 / 1e3)
    } else {
        format!("{ns} ns")
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_048_576 {
        format!("{:.2} MiB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

fn ratio(part: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        part as f64 * 100.0 / total as f64
    }
}

fn relative_delta_percent(baseline: u64, current: u64) -> Option<f64> {
    (baseline != 0).then(|| (current as f64 - baseline as f64) * 100.0 / baseline as f64)
}

fn comparison_row(
    ui: &mut egui::Ui,
    label: &str,
    baseline: u64,
    current: u64,
    formatter: impl Fn(u64) -> String,
) {
    ui.label(label);
    ui.label(formatter(baseline));
    ui.label(formatter(current));
    let delta = current as i128 - baseline as i128;
    let sign = if delta > 0 {
        "+"
    } else if delta < 0 {
        "−"
    } else {
        ""
    };
    let absolute = delta.unsigned_abs().min(u64::MAX as u128) as u64;
    let percent = relative_delta_percent(baseline, current)
        .map(|value| format!(" ({value:+.1}%)"))
        .unwrap_or_else(|| " (baseline is zero)".into());
    ui.label(format!("{sign}{}{percent}", formatter(absolute)));
    ui.end_row();
}

fn comparison_optional_latency_row(
    ui: &mut egui::Ui,
    label: &str,
    baseline: Option<u64>,
    current: Option<u64>,
) {
    match (baseline, current) {
        (Some(baseline), Some(current)) => {
            comparison_row(ui, label, baseline, current, format_duration)
        }
        _ => {
            ui.label(label);
            ui.label(format_latency(baseline));
            ui.label(format_latency(current));
            ui.label(RichText::new("Unavailable").color(MUTED));
            ui.end_row();
        }
    }
}

fn comparison_ratio_row(ui: &mut egui::Ui, label: &str, baseline: f64, current: f64) {
    ui.label(label);
    ui.label(format!("{baseline:.1}%"));
    ui.label(format!("{current:.1}%"));
    ui.label(format!("{:+.1} pp", current - baseline));
    ui.end_row();
}

fn evenly_sample_indices(length: usize, limit: usize) -> Vec<usize> {
    if length <= limit {
        return (0..length).collect();
    }
    (0..limit).map(|index| index * length / limit).collect()
}

fn operation_label(value: IoOperation) -> &'static str {
    match value {
        IoOperation::Read => "Read",
        IoOperation::Write => "Write",
        IoOperation::Flush => "Flush",
        IoOperation::Discard => "Discard",
        IoOperation::Other => "Other",
    }
}

fn access_label(value: AccessPattern) -> &'static str {
    match value {
        AccessPattern::Unknown => "Unknown",
        AccessPattern::Sequential => "Sequential",
        AccessPattern::Random => "Random",
    }
}

fn size_label(value: IoSizeClass) -> &'static str {
    match value {
        IoSizeClass::Small => "Small (<32 KiB)",
        IoSizeClass::Large => "Large (≥32 KiB)",
    }
}

fn pipeline_layer_label(value: PipelineLayer) -> &'static str {
    match value {
        PipelineLayer::Syscall => "UserSpace / Syscall",
        PipelineLayer::Vfs => "Kernel / VFS",
        PipelineLayer::Filesystem => "Kernel / Filesystem",
        PipelineLayer::PageCache => "Kernel / Page Cache",
        PipelineLayer::Writeback => "Kernel / Writeback",
        PipelineLayer::Bio => "Kernel / Bio",
        PipelineLayer::BlockQueue => "Kernel / Block Queue",
        PipelineLayer::BlockDevice => "Kernel / Block Device",
        PipelineLayer::Scsi => "Kernel / SCSI",
        PipelineLayer::Ufs => "Kernel / UFS",
        PipelineLayer::SchedulerContext => "Scheduler Context",
        PipelineLayer::UicContext => "UIC Context",
    }
}

fn pipeline_layer_y(value: PipelineLayer) -> f64 {
    match value {
        PipelineLayer::Syscall => 11.0,
        PipelineLayer::Vfs => 10.0,
        PipelineLayer::Filesystem => 9.0,
        PipelineLayer::PageCache => 8.0,
        PipelineLayer::Writeback => 7.0,
        PipelineLayer::Bio => 6.0,
        PipelineLayer::BlockQueue => 5.0,
        PipelineLayer::BlockDevice => 4.0,
        PipelineLayer::Scsi => 3.0,
        PipelineLayer::Ufs => 2.0,
        PipelineLayer::SchedulerContext => 1.5,
        PipelineLayer::UicContext => 1.0,
    }
}

fn pipeline_layer_color(value: PipelineLayer) -> Color32 {
    match value {
        PipelineLayer::Syscall => Color32::from_rgb(108, 174, 255),
        PipelineLayer::Vfs => Color32::from_rgb(88, 211, 181),
        PipelineLayer::Filesystem => Color32::from_rgb(116, 220, 120),
        PipelineLayer::PageCache => Color32::from_rgb(92, 205, 150),
        PipelineLayer::Writeback => Color32::from_rgb(174, 205, 92),
        PipelineLayer::Bio => Color32::from_rgb(219, 210, 96),
        PipelineLayer::BlockQueue => Color32::from_rgb(244, 197, 92),
        PipelineLayer::BlockDevice => Color32::from_rgb(255, 153, 85),
        PipelineLayer::Scsi => Color32::from_rgb(235, 118, 137),
        PipelineLayer::Ufs => Color32::from_rgb(190, 126, 255),
        PipelineLayer::SchedulerContext => Color32::from_rgb(120, 180, 205),
        PipelineLayer::UicContext => Color32::from_rgb(157, 166, 184),
    }
}

fn confidence_label(value: CorrelationConfidence) -> &'static str {
    match value {
        CorrelationConfidence::Exact => "Exact",
        CorrelationConfidence::Probable => "Probable",
        CorrelationConfidence::ContextOnly => "Context only",
    }
}

fn edge_confidence_label(value: EdgeConfidence) -> &'static str {
    match value {
        EdgeConfidence::Exact => "Exact",
        EdgeConfidence::Probable => "Probable",
        EdgeConfidence::ProbableAsync => "Probable async",
        EdgeConfidence::ContextOnly => "Context only",
    }
}

fn diagnostic_level_arg(value: DiagnosticLevel) -> &'static str {
    match value {
        DiagnosticLevel::Trace => "trace",
        DiagnosticLevel::Debug => "debug",
        DiagnosticLevel::Info => "info",
        DiagnosticLevel::Warn => "warn",
        DiagnosticLevel::Error => "error",
    }
}

fn graph_kind_duration_ms(
    graph: &android_ebpf_protocol::IoTransactionGraph,
    kind: IoNodeKind,
) -> Option<f64> {
    let mut found = false;
    let duration = graph
        .nodes
        .iter()
        .filter(|node| node.kind == kind)
        .map(|node| {
            found = true;
            node.duration_ns()
        })
        .sum::<u64>();
    found.then_some(duration as f64 / 1e6)
}

fn file_group_key(origins: &[FileOriginView]) -> String {
    match origins {
        [] => "Unattributed".into(),
        [origin] => origin
            .path
            .as_ref()
            .and_then(|path| path.path.clone())
            .unwrap_or_else(|| origin.file.fallback_label()),
        _ => format!("Multiple files ({})", origins.len()),
    }
}

fn axis_combo(ui: &mut egui::Ui, id: &str, label: &str, value: &mut AxisMetric) {
    ui.vertical(|ui| {
        ui.label(RichText::new(label).size(10.0).color(MUTED));
        egui::ComboBox::from_id_salt(id)
            .selected_text(value.label())
            .width(180.0)
            .show_ui(ui, |ui| {
                for metric in AxisMetric::ALL {
                    ui.selectable_value(value, metric, metric.label());
                }
            });
    });
}

fn summary_card(ui: &mut egui::Ui, label: &str, value: String) {
    card_frame().show(ui, |ui| {
        ui.label(
            RichText::new(label.to_uppercase())
                .size(10.0)
                .strong()
                .color(MUTED),
        );
        ui.add_space(5.0);
        ui.label(RichText::new(value).size(20.0).strong().color(TEXT));
    });
}

#[cfg(test)]
mod ui_tests {
    use super::*;
    use android_ebpf_protocol::{FileIdentity, PathSnapshot, PathSource};

    #[test]
    fn workflow_starts_with_connect_and_advances_after_device_selection() {
        let mut app = StudioApp::default();
        assert_eq!(app.setup_step(), SetupStep::Connect);
        assert_eq!(app.page, Page::Overview);

        app.selected_serial = Some("device-01".into());
        assert_eq!(app.setup_step(), SetupStep::Verify);
    }

    #[test]
    fn explorer_sampling_is_bounded_and_spans_the_session() {
        let indices = evenly_sample_indices(100_000, 2_000);
        assert_eq!(indices.len(), 2_000);
        assert_eq!(indices[0], 0);
        assert!(indices.last().is_some_and(|index| *index >= 99_900));
        assert!(indices.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn file_group_uses_path_and_preserves_multiple_origins() {
        let origin = FileOriginView {
            file: FileIdentity {
                fs_device_major: 259,
                fs_device_minor: 7,
                inode: 42,
                inode_generation: None,
                mount_id: Some(1),
            },
            path: Some(PathSnapshot {
                path: Some("/data/test.bin".into()),
                source: PathSource::ProcFd,
                captured_ts_ns: 100,
                deleted: false,
            }),
            confidence: EdgeConfidence::Probable,
        };
        assert_eq!(
            file_group_key(std::slice::from_ref(&origin)),
            "/data/test.bin"
        );
        assert_eq!(
            file_group_key(&[origin.clone(), origin]),
            "Multiple files (2)"
        );
        assert_eq!(file_group_key(&[]), "Unattributed");
    }

    #[test]
    fn explorer_presets_select_stable_queries() {
        assert_eq!(
            ExplorerPreset::LatencyByFile.query(),
            Some((
                AxisMetric::TimeMs,
                AxisMetric::TotalLatencyMs,
                GroupBy::File
            ))
        );
        assert_eq!(
            ExplorerPreset::QueuePressure.query(),
            Some((
                AxisMetric::QueueDepth,
                AxisMetric::TotalLatencyMs,
                GroupBy::Direction
            ))
        );
        assert_eq!(ExplorerPreset::Custom.query(), None);
    }

    #[test]
    fn comparison_delta_is_signed_and_zero_baseline_is_unavailable() {
        assert_eq!(relative_delta_percent(100, 125), Some(25.0));
        assert_eq!(relative_delta_percent(100, 75), Some(-25.0));
        assert_eq!(relative_delta_percent(0, 25), None);
    }
}
