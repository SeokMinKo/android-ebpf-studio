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
    IoPipeline, IoSizeClass, IoTransactionGraph, PipelineLayer, ProbeCapabilities, SegmentRecord,
    SlowReason, StackFingerprintRecord, TriggerRecord, WireRecord,
};
use crossbeam_channel::{Receiver, Sender, bounded};
use eframe::egui::{self, Color32, RichText, Stroke};
use egui_plot::{HoverPosition, Legend, Line, Plot, PlotPoints, Points};

use crate::{
    adb::{AdbClient, AdbDevice, DeviceState, PreflightReport},
    artifacts::{CapturePaths, create_default_session_path},
    capture::{self, CaptureHandle, HostMessage},
    diagnostics::{RotatingJsonl, export_bundle, host_record},
    performance::{LatencySnapshot, UiPerformanceMonitor},
    session::{self, AsyncSessionWriter},
    simulator,
};

const MAX_RECENT: usize = 2_000;
const MAX_EXPLORER_POINTS: usize = 12_000;
const MAX_GRAPH_EXPLORER_POINTS: usize = 2_000;
const MAX_EXPLORER_GROUPS: usize = 32;
const MAX_MESSAGES_PER_FRAME: usize = 1_000;
const LIVE_ANALYSIS_REFRESH: Duration = Duration::from_millis(250);
const PERFORMANCE_WARNING_INTERVAL: Duration = Duration::from_secs(10);
include!("analysis_ui.rs");
include!("qa.rs");
include!("selection.rs");
include!("graph_summary_ui.rs");
include!("footprint_ui.rs");
include!("window_series_ui.rs");
include!("timeline_ui.rs");
include!("scheduler_ui.rs");
include!("host_bw_ui.rs");
include!("plot_style.rs");
include!("axis_range.rs");
include!("reanalysis.rs");
include!("file_evidence.rs");
include!("plot_sampling.rs");
include!("view_export.rs");
include!("ui_layout.rs");
include!("page_purpose.rs");
include!("compare_explore.rs");
include!("perfetto_ui.rs");
fn bg() -> Color32 {
    palette_color(0, Color32::from_rgb(12, 17, 27))
}
fn panel() -> Color32 {
    palette_color(1, Color32::from_rgb(20, 27, 40))
}
fn panel_raised() -> Color32 {
    palette_color(2, Color32::from_rgb(27, 36, 52))
}
fn border() -> Color32 {
    palette_color(3, Color32::from_rgb(48, 61, 82))
}
fn ink() -> Color32 {
    palette_color(4, Color32::from_rgb(232, 238, 248))
}
fn muted() -> Color32 {
    palette_color(5, Color32::from_rgb(145, 158, 181))
}
fn accent() -> Color32 {
    palette_color(6, Color32::from_rgb(74, 144, 245))
}
fn green() -> Color32 {
    palette_color(7, Color32::from_rgb(63, 201, 145))
}
fn amber() -> Color32 {
    palette_color(8, Color32::from_rgb(245, 181, 65))
}
fn red() -> Color32 {
    palette_color(9, Color32::from_rgb(242, 102, 112))
}

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
    ChunkTimeline,
    QueueTimeline,
    IssueGapTimeline,
    CompletionGapTimeline,
    NormalizedLatencyTimeline,
    CpuTimeline,
    WindowBandwidth,
    WindowIops,
    CumulativePayload,
    WindowBusyPercent,
    WindowBusyMs,
    WindowIdleMs,
    RollingC2cBandwidth,
    RollingD2dBandwidth,
    BusyIntervals,
    IdleIntervals,
    BurstPayload,
    ConnectedFootprint,
    CommandTimeline,
    RequestGantt,
    CpuEvents,
    SchedulerIoWait,
}

impl ExplorerPreset {
    const ALL: [Self; 28] = [
        Self::LatencyTimeline,
        Self::LatencyByFile,
        Self::QueuePressure,
        Self::LayerContribution,
        Self::LbaDistribution,
        Self::Custom,
        Self::ChunkTimeline,
        Self::QueueTimeline,
        Self::IssueGapTimeline,
        Self::CompletionGapTimeline,
        Self::NormalizedLatencyTimeline,
        Self::CpuTimeline,
        Self::WindowBandwidth,
        Self::WindowIops,
        Self::CumulativePayload,
        Self::WindowBusyPercent,
        Self::WindowBusyMs,
        Self::WindowIdleMs,
        Self::RollingC2cBandwidth,
        Self::RollingD2dBandwidth,
        Self::BusyIntervals,
        Self::IdleIntervals,
        Self::BurstPayload,
        Self::ConnectedFootprint,
        Self::CommandTimeline,
        Self::RequestGantt,
        Self::CpuEvents,
        Self::SchedulerIoWait,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::LatencyTimeline => "Latency over time",
            Self::LatencyByFile => "Latency by file",
            Self::QueuePressure => "Queue depth vs latency",
            Self::LayerContribution => "Filesystem vs UFS",
            Self::LbaDistribution => "LBA distribution",
            Self::Custom => "Custom",
            Self::ChunkTimeline => "Chunk size over time",
            Self::QueueTimeline => "Queue depth over time",
            Self::IssueGapTimeline => "D2D issue gap over time",
            Self::CompletionGapTimeline => "C2C completion gap over time",
            Self::NormalizedLatencyTimeline => "Latency per KiB over time",
            Self::CpuTimeline => "Issue CPU over time",
            Self::WindowBandwidth => "Bandwidth by time window",
            Self::WindowIops => "IOPS by time window",
            Self::CumulativePayload => "Cumulative transferred data",
            Self::WindowBusyPercent => "Device busy % over time",
            Self::WindowBusyMs => "Active time by window",
            Self::WindowIdleMs => "Idle time by window",
            Self::RollingC2cBandwidth => "Rolling C2C bandwidth",
            Self::RollingD2dBandwidth => "Rolling D2D bandwidth",
            Self::BusyIntervals => "Continuous busy intervals",
            Self::IdleIntervals => "Continuous idle intervals",
            Self::BurstPayload => "Cumulative data within bursts",
            Self::ConnectedFootprint => "Connected LBA footprint",
            Self::CommandTimeline => "Block command timeline",
            Self::RequestGantt => "Request Gantt",
            Self::CpuEvents => "Issue / completion CPU timeline",
            Self::SchedulerIoWait => "Scheduler I/O wait over time",
        }
    }

    fn query(self) -> Option<(AxisMetric, AxisMetric, GroupBy)> {
        use crate::window_series::WindowMetric;
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
            Self::LbaDistribution | Self::ConnectedFootprint => {
                Some((AxisMetric::TimeMs, AxisMetric::Sector, GroupBy::Direction))
            }
            Self::Custom => None,
            Self::SchedulerIoWait => Some((
                AxisMetric::TimeMs,
                AxisMetric::SchedulerIoWait,
                GroupBy::None,
            )),
            Self::CommandTimeline => Some((
                AxisMetric::TimeMs,
                AxisMetric::Timeline(TimelineMode::Commands),
                GroupBy::Direction,
            )),
            Self::CpuEvents => Some((
                AxisMetric::TimeMs,
                AxisMetric::Timeline(TimelineMode::Cpus),
                GroupBy::Direction,
            )),
            Self::RequestGantt => Some((
                AxisMetric::TimeMs,
                AxisMetric::Timeline(TimelineMode::Requests),
                GroupBy::Direction,
            )),
            Self::ChunkTimeline => {
                Some((AxisMetric::TimeMs, AxisMetric::ChunkKiB, GroupBy::Direction))
            }
            Self::QueueTimeline => Some((
                AxisMetric::TimeMs,
                AxisMetric::IssueQueueDepth,
                GroupBy::Direction,
            )),
            Self::IssueGapTimeline => Some((
                AxisMetric::TimeMs,
                AxisMetric::IssueGapMs,
                GroupBy::Direction,
            )),
            Self::CompletionGapTimeline => Some((
                AxisMetric::TimeMs,
                AxisMetric::CompletionGapMs,
                GroupBy::Direction,
            )),
            Self::NormalizedLatencyTimeline => Some((
                AxisMetric::TimeMs,
                AxisMetric::LatencyPerKiB,
                GroupBy::Direction,
            )),
            Self::CpuTimeline => Some((AxisMetric::TimeMs, AxisMetric::IssueCpu, GroupBy::Process)),
            Self::RollingC2cBandwidth => Some((
                AxisMetric::TimeMs,
                AxisMetric::RollingC2cBandwidth,
                GroupBy::Direction,
            )),
            Self::RollingD2dBandwidth => Some((
                AxisMetric::TimeMs,
                AxisMetric::RollingD2dBandwidth,
                GroupBy::Direction,
            )),
            Self::BurstPayload => Some((
                AxisMetric::TimeMs,
                AxisMetric::Window(WindowMetric::BurstPayload),
                GroupBy::Direction,
            )),
            Self::BusyIntervals => Some((
                AxisMetric::TimeMs,
                AxisMetric::Window(WindowMetric::BusyRunMs),
                GroupBy::None,
            )),
            Self::IdleIntervals => Some((
                AxisMetric::TimeMs,
                AxisMetric::Window(WindowMetric::IdleGapMs),
                GroupBy::None,
            )),
            Self::WindowBandwidth => Some((
                AxisMetric::TimeMs,
                AxisMetric::Window(WindowMetric::Bandwidth),
                GroupBy::Direction,
            )),
            Self::WindowIops => Some((
                AxisMetric::TimeMs,
                AxisMetric::Window(WindowMetric::Iops),
                GroupBy::Direction,
            )),
            Self::CumulativePayload => Some((
                AxisMetric::TimeMs,
                AxisMetric::Window(WindowMetric::CumulativePayload),
                GroupBy::Direction,
            )),
            Self::WindowBusyPercent => Some((
                AxisMetric::TimeMs,
                AxisMetric::Window(WindowMetric::BusyPercent),
                GroupBy::None,
            )),
            Self::WindowBusyMs => Some((
                AxisMetric::TimeMs,
                AxisMetric::Window(WindowMetric::BusyMs),
                GroupBy::None,
            )),
            Self::WindowIdleMs => Some((
                AxisMetric::TimeMs,
                AxisMetric::Window(WindowMetric::IdleMs),
                GroupBy::None,
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
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
    IssueQueueDepth,
    IssueGapMs,
    CompletionGapMs,
    LatencyPerKiB,
    IssueCpu,
    RollingC2cBandwidth,
    RollingD2dBandwidth,
    Window(crate::window_series::WindowMetric),
    Timeline(TimelineMode),
    SchedulerIoWait,
}

impl AxisMetric {
    const ALL: [Self; 19] = [
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
        Self::IssueQueueDepth,
        Self::IssueGapMs,
        Self::CompletionGapMs,
        Self::LatencyPerKiB,
        Self::IssueCpu,
        Self::RollingC2cBandwidth,
        Self::RollingD2dBandwidth,
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
            Self::QueueDepth => "QD after completion (all devices)",
            Self::FilesystemLatencyMs => "Filesystem latency (ms)",
            Self::UfsLatencyMs => "UFS latency (ms)",
            Self::CriticalPathMs => "Critical path (ms)",
            Self::IssueQueueDepth => "Observed QD at issue (device)",
            Self::IssueGapMs => "D2D issue gap (ms)",
            Self::CompletionGapMs => "C2C completion gap (ms)",
            Self::LatencyPerKiB => "Device latency (ms/KiB)",
            Self::IssueCpu => "Issue CPU",
            Self::RollingC2cBandwidth => "Rolling C2C BW (MiB/s)",
            Self::RollingD2dBandwidth => "Rolling D2D BW (MiB/s)",
            Self::Window(metric) => metric.label(),
            Self::Timeline(mode) => mode.label(),
            Self::SchedulerIoWait => "Scheduler I/O wait (us)",
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
            Self::TotalLatencyMs => io.total_latency_ns.map(|n| n as f64 / 1e6),
            Self::QueueLatencyMs => io.queue_latency_ns.map(|value| value as f64 / 1e6),
            Self::DeviceLatencyMs => io.device_latency_ns.map(|n| n as f64 / 1e6),
            Self::Pid => io.issuer_pid().map(|pid| pid as f64),
            Self::QueueDepth => io.queue_depth_after.map(|n| n as f64),
            Self::IssueQueueDepth => io.detail_timing.issue_depth.map(|n| n as f64),
            Self::IssueGapMs => io.detail_timing.issue_gap_ns.map(|n| n as f64 / 1e6),
            Self::CompletionGapMs => io.detail_timing.completion_gap_ns.map(|n| n as f64 / 1e6),
            Self::LatencyPerKiB => {
                if matches!(io.issue.operation, IoOperation::Read | IoOperation::Write)
                    && io.issue.bytes > 0
                {
                    io.device_latency_ns
                        .map(|n| n as f64 / 1e6 / (io.issue.bytes as f64 / 1024.))
                } else {
                    None
                }
            }
            Self::IssueCpu => io.issuer_cpu().map(|n| n as f64),
            Self::RollingC2cBandwidth => io
                .detail_timing
                .completion_bandwidth
                .as_ref()
                .and_then(|r| r.mib_s()),
            Self::RollingD2dBandwidth => io
                .detail_timing
                .issue_bandwidth
                .as_ref()
                .and_then(|r| r.mib_s()),
            Self::Window(_) | Self::Timeline(_) | Self::SchedulerIoWait => None,
            Self::FilesystemLatencyMs => {
                graph.and_then(|graph| graph_kind_duration_ms(graph, IoNodeKind::Filesystem))
            }
            Self::UfsLatencyMs => {
                graph.and_then(|graph| graph_kind_duration_ms(graph, IoNodeKind::UfsCommand))
            }
            Self::CriticalPathMs => {
                if io.evidence.is_some() {
                    None
                } else {
                    graph.map(|graph| graph.metrics().critical_path_ns as f64 / 1e6)
                }
            }
        }
    }

    fn is_storage_address(self) -> bool {
        matches!(self, Self::Sector | Self::AddressKiB)
    }

    fn format_value(self, value: f64) -> String {
        match self {
            Self::Sector
            | Self::Pid
            | Self::QueueDepth
            | Self::IssueQueueDepth
            | Self::IssueCpu => format!("{value:.0}"),
            Self::AddressKiB | Self::ChunkKiB => format!("{value:.1}"),
            Self::TimeMs
            | Self::TotalLatencyMs
            | Self::QueueLatencyMs
            | Self::DeviceLatencyMs
            | Self::FilesystemLatencyMs
            | Self::UfsLatencyMs
            | Self::CriticalPathMs
            | Self::IssueGapMs
            | Self::CompletionGapMs
            | Self::LatencyPerKiB
            | Self::RollingC2cBandwidth
            | Self::RollingD2dBandwidth
            | Self::Window(_)
            | Self::Timeline(_)
            | Self::SchedulerIoWait => format!("{value:.3}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
            Self::Process => format!(
                "{} ({})",
                io.issue.comm,
                io.issuer_pid()
                    .map_or("PID unavailable".into(), |n| n.to_string())
            ),
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
                    Self::Confidence => format!("{:?}", path_confidence(&origins)),
                    _ => unreachable!(),
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
struct ExplorerPoint {
    coordinates: [f64; 2],
    file_tooltip: Option<String>,
    request: IoSelectionKey,
}

#[derive(Debug, Clone)]
struct ExplorerView {
    generation: u64,
    x_axis: AxisMetric,
    y_axis: AxisMetric,
    group_by: GroupBy,
    groups: Vec<(String, Vec<ExplorerPoint>)>,
    available: usize,
    displayed: usize,
    built_at: Instant,
}

#[derive(Debug, Clone)]
struct PipelineView {
    generation: u64,
    io: CompletedIo,
    pipeline: IoPipeline,
    graph: IoTransactionGraph,
    graph_metrics: GraphMetrics,
    origins: Vec<FileOriginView>,
    slow_reason: Option<SlowReason>,
    built_at: Instant,
}

struct ComparisonBaseline {
    viewer: Box<StudioApp>,
    path: PathBuf,
    summary: AnalysisSummary,
    rejected_records: u64,
    capabilities: Option<ProbeCapabilities>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum CapturePhase {
    #[default]
    Ready,
    Preparing,
    Recording,
    Stopping,
    Analyzing,
    Complete,
    Error,
}
impl CapturePhase {
    fn busy(self) -> bool {
        matches!(
            self,
            Self::Preparing | Self::Recording | Self::Stopping | Self::Analyzing
        )
    }
    fn label(self) -> &'static str {
        match self {
            Self::Ready => "Ready",
            Self::Preparing => "Preparing",
            Self::Recording => "Recording",
            Self::Stopping => "Stopping",
            Self::Analyzing => "Analyzing",
            Self::Complete => "Complete",
            Self::Error => "Error",
        }
    }
}

pub struct StudioApp {
    activity: Arc<crate::host_bw::ActivityTimeline>,
    footprint: FootprintState,
    window_width_ms: u64,
    reanalysis: ReanalysisState,
    file_evidence_positions: Option<Vec<usize>>,
    selection: SelectionState,
    scheduler: SchedulerState,
    plot_style: PlotStyle,
    render_qa: RenderQa,
    render_qa_scale: Option<f32>,
    close_after_capture: bool,
    phase: CapturePhase,
    started_at: Option<Instant>,
    capture_error: Option<String>,
    loss_status: String,
    source_info: Vec<WireRecord>,
    raw_export_pending: bool,
    discovery_pending: bool,
    last_discovery: Option<Instant>,
    theme: ThemeChoice,
    adb: AdbClient,
    tx: Sender<HostMessage>,
    rx: Receiver<HostMessage>,
    devices: Vec<AdbDevice>,
    selected_serial: Option<String>,
    preflight: Option<PreflightReport>,
    status: String,
    diagnostics: VecDeque<DiagnosticRecord>,
    analyzer: AnalysisEngine,
    query: AnalysisFilter,
    disk_stats: Vec<WireRecord>,
    disk_stats_view: DiskStatsView,
    filtered: Option<AnalysisEngine>,
    filtered_generation: u64,
    filter_edit_epoch: u64,
    trend_view: Option<(u64, TrendData)>,
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
    selected_pipeline_request: Option<IoSelectionKey>,
    analysis_generation: u64,
    explorer_view: Option<ExplorerView>,
    pipeline_view: Option<PipelineView>,
    summary_view: Option<(u64, Instant, AnalysisSummary)>,
    comparison: Option<ComparisonBaseline>,
    compare_explore: CompareExplore,
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
    performance: UiPerformanceMonitor,
    last_performance_warning: Instant,
}

impl Default for StudioApp {
    fn default() -> Self {
        let (tx, rx) = bounded(20_000);
        Self {
            activity: Arc::default(),
            footprint: FootprintState::default(),
            window_width_ms: 1000,
            reanalysis: ReanalysisState::default(),
            file_evidence_positions: None,
            scheduler: SchedulerState::default(),
            selection: SelectionState {
                enabled: true,
                auto_bounds: true,
                ..Default::default()
            },
            plot_style: PlotStyle::default(),
            render_qa: RenderQa::default(),
            render_qa_scale: None,
            close_after_capture: false,
            phase: CapturePhase::Ready,
            started_at: None,
            capture_error: None,
            loss_status: "Loss counters not reported".into(),
            source_info: Vec::new(),
            raw_export_pending: false,
            discovery_pending: false,
            last_discovery: None,
            theme: ThemeChoice::System,
            adb: AdbClient::default(),
            tx,
            rx,
            devices: Vec::new(),
            selected_serial: None,
            preflight: None,
            status: "Ready".into(),
            diagnostics: VecDeque::new(),
            analyzer: AnalysisEngine::new(),
            disk_stats: Vec::new(),
            disk_stats_view: DiskStatsView::default(),
            query: AnalysisFilter::default(),
            filtered: None,
            filtered_generation: u64::MAX,
            filter_edit_epoch: 0,
            trend_view: None,
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
            compare_explore: CompareExplore::default(),
            capture_mode: CaptureMode::Deep,
            filter_pid: 0,
            filter_operation: None,
            filter_min_bytes: 0,
            slow_threshold_ms: 5.0,
            control_generation: 1,
            control_status: "Deep · automatic file attribution".into(),
            latest_aggregate: None,
            heavy_hitters: Vec::new(),
            triggers: VecDeque::new(),
            segments: VecDeque::new(),
            stack_fingerprints: VecDeque::new(),
            performance: UiPerformanceMonitor::default(),
            last_performance_warning: Instant::now(),
        }
    }
}

impl StudioApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut app = Self::default();
        if let Some(storage) = cc.storage {
            app.theme = eframe::get_value(storage, "theme").unwrap_or_default();
            app.plot_style = eframe::get_value(storage, "plot-style-v1").unwrap_or_default();
            app.plot_style.normalize();
            app.group_by =
                eframe::get_value(storage, "plot-color-category-v1").unwrap_or(GroupBy::Direction);
        }
        if app.group_by != GroupBy::Direction {
            app.explorer_preset = ExplorerPreset::Custom;
        }
        app.initialize_render_qa();
        if app.render_qa.output.is_some() {
            cc.egui_ctx
                .memory_mut(|memory| *memory = egui::Memory::default());
            app.plot_style = PlotStyle::default();
            app.group_by = GroupBy::Direction;
        }
        app
    }
    fn is_running(&self) -> bool {
        self.phase.busy() || self.capture.is_some() || self.simulator_stop.is_some()
    }

    #[allow(dead_code)]
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
        if self.discovery_pending || self.is_running() {
            return;
        }
        self.discovery_pending = true;
        self.last_discovery = Some(Instant::now());
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
                self.phase = CapturePhase::Error;
                self.status = format!(
                    "Cannot create session: {error}. Check free space and folder access, then retry Start."
                );
                self.push_diagnostic(error.to_string());
                false
            }
        }
    }

    fn start_device(&mut self) {
        if self.is_running() {
            return;
        }
        let Some(serial) = self.selected_serial.clone() else {
            self.push_diagnostic("Select an authorized device first".into());
            return;
        };
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
                self.phase = CapturePhase::Error;
                self.status = format!(
                    "Cannot create capture log: {error}. Check disk space and folder access, then retry."
                );
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
        self.preflight = None;
        self.phase = CapturePhase::Preparing;
        self.started_at = Some(Instant::now());
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
        if self.is_running() {
            return;
        }
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
        self.phase = CapturePhase::Recording;
        self.started_at = Some(Instant::now());
    }

    fn stop(&mut self) {
        if !matches!(
            self.phase,
            CapturePhase::Preparing | CapturePhase::Recording
        ) {
            return;
        }
        if let Some(handle) = &self.capture {
            handle.stop();
        }
        if let Some(stop) = &self.simulator_stop {
            stop.store(true, Ordering::Release);
        }
        self.phase = CapturePhase::Stopping;
        self.status = "Stopping: draining collector output…".into();
    }

    fn apply_capture_control(&mut self) {
        if self
            .preflight
            .as_ref()
            .is_some_and(|r| r.perfetto && !r.full_ebpf_ready())
        {
            self.control_status =
                "Perfetto: all available block events; apply analysis filters after Stop".into();
            return;
        }
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
                pids: (self.filter_pid != 0)
                    .then_some(self.filter_pid)
                    .into_iter()
                    .collect(),
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
        match handle.send_control(&CaptureControlCommand::ApplyConfig {
            config: Box::new(config),
        }) {
            Ok(()) => {
                self.control_status = format!("Applying generation {generation}…");
            }
            Err(error) => self.push_diagnostic(error),
        }
    }

    fn finish_session(&mut self) {
        self.phase = CapturePhase::Analyzing;
        if let Some(writer) = self.writer.take() {
            let tx = self.tx.clone();
            let seen = self.received_events;
            let rejected = self.rejected_records;
            let graceful = self.agent_graceful == Some(true) && self.capture_error.is_none();
            std::thread::spawn(move || {
                let result = writer
                    .finish(seen, rejected, graceful)
                    .map_err(|e| e.to_string());
                let _ = tx.send(HostMessage::Finalized(result));
            });
        } else {
            let _ = self.tx.try_send(HostMessage::Finalized(Ok(())));
        }
    }

    fn open_session(&mut self) {
        if self.is_running() {
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
        self.phase = CapturePhase::Analyzing;
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
        self.activity = loaded.activity;
        self.footprint.view = None;
        self.footprint.pending = None;
        self.footprint.fit = true;
        self.reanalysis.source_start_ns = Some(loaded.source_start_ns);
        self.reanalysis.source_end_ns = loaded.source_end_ns;
        self.reanalysis.source_count = loaded.source_completed_ios;
        self.reanalysis.window = loaded.window_ns;
        self.reanalysis.elapsed_ms = loaded.load_elapsed_ms;
        let (a, b) = loaded
            .window_ns
            .unwrap_or((loaded.source_start_ns, loaded.source_end_ns));
        self.reanalysis.draft = [
            ((a - loaded.source_start_ns) as f64 / 1e6).to_string(),
            ((b - loaded.source_start_ns) as f64 / 1e6).to_string(),
        ];
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
        self.selection = SelectionState {
            enabled: true,
            auto_bounds: true,
            ..Default::default()
        };
        self.query = AnalysisFilter::default();
        self.filtered = None;
        self.filtered_generation = u64::MAX;
        self.file_evidence_positions = None;
        self.trend_view = None;
        self.phase = CapturePhase::Complete;
        self.selected_pipeline_request = None;
        self.loss_status = loaded.loss_status;
        self.source_info = loaded.source_info;
        self.disk_stats = loaded.disk_stats;
        self.disk_stats_view = DiskStatsView::default();
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
        self.start_comparison_load(path);
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
                    self.discovery_pending = false;
                    if self.is_running() {
                        continue;
                    }
                    let previous = self.selected_serial.clone();
                    let available: Vec<_> = devices
                        .iter()
                        .filter(|d| d.state == DeviceState::Device)
                        .collect();
                    self.selected_serial = previous
                        .clone()
                        .filter(|p| available.iter().any(|d| &d.serial == p))
                        .or_else(|| (available.len() == 1).then(|| available[0].serial.clone()));
                    if previous != self.selected_serial || self.devices != devices {
                        self.preflight = None;
                    }
                    if self.phase == CapturePhase::Ready {
                        self.status =
                            if devices.iter().any(|d| d.state == DeviceState::Unauthorized) {
                                "Approve USB debugging on the phone, then Start".into()
                            } else if available.is_empty() {
                                "Connect a rooted Android phone with USB debugging".into()
                            } else if self.selected_serial.is_none() {
                                "Select the phone to analyze".into()
                            } else {
                                "Ready: Start automatically prepares the phone".into()
                            };
                    }
                    self.devices = devices;
                }
                HostMessage::Devices(Err(error)) | HostMessage::Preflight(Err(error)) => {
                    self.discovery_pending = false;
                    self.status = format!("Device check failed: {error}");
                    self.preflight = None;
                    self.push_diagnostic(error)
                }
                HostMessage::Preflight(Ok(report)) => {
                    if self.selected_serial.as_deref() != Some(report.serial.as_str()) {
                        continue;
                    }
                    self.status = if report.full_ebpf_ready() {
                        "Full eBPF preflight passed".into()
                    } else if report.perfetto {
                        "Perfetto available · FilePath unavailable · event support checked during capture".into()
                    } else if !report.root {
                        "Root unavailable · checking accessible device counters".into()
                    } else {
                        "Preflight incomplete — see capabilities".into()
                    };
                    self.preflight = Some(report);
                }
                HostMessage::Status(status) => self.status = status,
                HostMessage::AnalysisStarted => {
                    self.phase = CapturePhase::Analyzing;
                    self.status = "Analyzing Perfetto block observations…".into();
                }
                HostMessage::Record(record) => self.ingest_record(record),
                HostMessage::Diagnostic(value) => self.push_diagnostic_record(value),
                HostMessage::SessionLoaded(path, Ok(loaded)) => {
                    self.apply_loaded_session(path, *loaded);
                }
                HostMessage::SessionLoaded(_, Err(error)) => {
                    self.phase = CapturePhase::Error;
                    self.status = error.clone();
                    self.push_diagnostic(error);
                }
                HostMessage::ViewExported(result) => {
                    self.status = match result {
                        Ok(path) => format!("Analysis view exported → {}", path.display()),
                        Err(error) => format!("View export failed: {error}"),
                    };
                }
                HostMessage::Exported(Ok(summary)) => {
                    self.status = format!("Exported CSV and {}", summary.display());
                }
                HostMessage::RawTraceExported(result) => {
                    self.raw_export_pending = false;
                    let status = match result {
                        Ok(path) => format!("Perfetto raw trace exported → {}", path.display()),
                        Err(error) => format!("Raw trace export failed: {error}"),
                    };
                    if self.is_running() {
                        self.push_diagnostic(status);
                    } else {
                        self.status = status;
                    }
                }
                HostMessage::Exported(Err(error)) => self.push_diagnostic(error),
                HostMessage::Ended(result) => {
                    self.capture_error =
                        result.as_ref().err().cloned().or(self.capture_error.take());
                    self.status = match &result {
                        Err(error) => format!("Capture failed: {error}"),
                        Ok(()) if self.agent_footer_seen && self.agent_graceful == Some(true) => {
                            "Capture completed".into()
                        }
                        Ok(()) => "Capture stopped (partial session)".into(),
                    };
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
                HostMessage::Finalized(result) => {
                    if let Err(error) = result {
                        self.capture_error = Some(error);
                    }
                    self.page = Page::Overview;
                    self.phase = if self.capture_error.is_some() {
                        CapturePhase::Error
                    } else {
                        CapturePhase::Complete
                    };
                    if let Some(error) = &self.capture_error {
                        self.status = format!(
                            "Partial data preserved: {error}. Free space/reconnect and retry Start."
                        );
                    } else {
                        self.status = format!(
                            "Analysis ready · {}",
                            if self.agent_graceful == Some(true) {
                                "session saved"
                            } else {
                                "partial session saved; footer absent"
                            }
                        );
                    }
                }
            }
        }
        self.performance
            .observe_message_drain(started.elapsed(), self.rx.len());
    }

    fn ingest_record(&mut self, record: WireRecord) {
        if matches!(
            &record,
            WireRecord::SourceInfo { .. } | WireRecord::Footer { .. }
        ) {
            Arc::make_mut(&mut self.activity).observe_record(&record);
        }
        if let WireRecord::Footer { graceful, .. } = &record {
            self.agent_footer_seen = true;
            self.agent_graceful = *graceful;
        }
        if !matches!(&record, WireRecord::Footer { .. })
            && let Some(writer) = self.writer.as_ref()
            && let Err(error) = writer.append(record.clone())
        {
            self.rejected_records += 1;
            self.capture_error = Some(error.to_string());
            self.push_diagnostic(error.to_string());
            self.stop();
        }
        match record {
            value @ WireRecord::SourceInfo { .. } => {
                let WireRecord::SourceInfo {
                    source,
                    status,
                    metadata,
                    ..
                } = &value
                else {
                    unreachable!()
                };
                if source != "scheduler_iowait" {
                    self.loss_status = status.clone();
                }
                if metadata.get("stage").and_then(|s| s.as_str()) == Some("recording")
                    && self.phase == CapturePhase::Preparing
                {
                    self.phase = CapturePhase::Recording;
                }
                if metadata.get("stage").and_then(|s| s.as_str()) == Some("complete") {
                    self.push_diagnostic(format!("{source} source quality: {metadata}"));
                }
                self.source_info.push(value);
            }
            value @ WireRecord::DiskStats { .. } => {
                self.disk_stats.push(value);
                if self.phase == CapturePhase::Preparing {
                    self.phase = CapturePhase::Recording;
                }
            }
            WireRecord::Event {
                sequence, event, ..
            } => {
                if let Some(previous) = self.last_sequence
                    && sequence != previous.saturating_add(1)
                {
                    Arc::make_mut(&mut self.activity).limitation =
                        Some("Event sequence gap in the received stream".into());
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
                if let Some((a, b)) = session::event_interval(&event) {
                    Arc::make_mut(&mut self.activity).observe_range(a, b);
                }
                if let Some(completed) = self.analyzer.ingest(event) {
                    Arc::make_mut(&mut self.activity).observe(&completed);
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
                self.loss_status = format!(
                    "Kernel loss: {} · userspace loss: {userspace_drops} · ambiguous: {correlation_ambiguous} · expired: {correlation_expired}",
                    kernel_drops.map_or_else(|| "not reported".into(), |v| v.to_string())
                );
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
                if self.phase == CapturePhase::Preparing {
                    self.phase = CapturePhase::Recording;
                    self.apply_capture_control();
                }
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
                        acknowledgement
                            .reason
                            .as_deref()
                            .unwrap_or("unknown reason")
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
        self.scheduler = SchedulerState::default();
        self.activity = Arc::default();
        self.footprint = FootprintState::default();
        self.reanalysis = ReanalysisState::default();
        self.file_evidence_positions = None;
        self.selection = SelectionState {
            enabled: true,
            auto_bounds: true,
            ..Default::default()
        };
        self.trend_view = None;
        self.query = AnalysisFilter::default();
        self.filtered = None;
        self.capture_error = None;
        self.loss_status = "Loss counters not reported".into();
        self.source_info.clear();
        self.disk_stats.clear();
        self.disk_stats_view = DiskStatsView::default();
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
        self.performance.reset();
        self.last_performance_warning = Instant::now();
    }

    fn maybe_emit_performance_warning(&mut self) {
        if !self.is_running()
            || self.last_performance_warning.elapsed() < PERFORMANCE_WARNING_INTERVAL
        {
            return;
        }
        let snapshot = self.performance.snapshot();
        if snapshot.ui_update.p95_ms <= 33.0 && snapshot.current_backlog < 1_000 {
            return;
        }
        self.last_performance_warning = Instant::now();
        let mut record = host_record(
            self.session_id.as_deref().unwrap_or("session"),
            DiagnosticLevel::Warn,
            "ui.performance",
            "UI_PERFORMANCE_DEGRADED",
            "degraded",
            Some(format!(
                "ui_p95_ms={:.3} ui_max_ms={:.3} backlog={} peak_backlog={} explorer_p95_ms={:.3} pipeline_p95_ms={:.3}",
                snapshot.ui_update.p95_ms,
                snapshot.ui_update.max_ms,
                snapshot.current_backlog,
                snapshot.peak_backlog,
                snapshot.explorer_rebuild.p95_ms,
                snapshot.pipeline_rebuild.p95_ms,
            )),
        );
        record.duration_ms = Some(snapshot.ui_update.p95_ms.round().max(0.0) as u64);
        record.count = Some(snapshot.current_backlog as u64);
        self.push_diagnostic_record(record);
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
            "ui_performance": self.performance.snapshot(),
            "capture_efficiency": self.latest_aggregate.as_ref().map(|snapshot| serde_json::json!({
                "observed": snapshot.counters.observed,
                "bytes": snapshot.counters.bytes,
                "detail_emitted": snapshot.counters.detail_emitted,
                "suppressed_fast": snapshot.counters.suppressed_fast,
                "filter_suppressed": snapshot.counters.filter_suppressed,
                "ring_reserve_failures": snapshot.counters.ring_reserve_failures,
                "map_insert_failures": snapshot.counters.map_insert_failures,
            })),
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
            let started = Instant::now();
            let mut summary = self.analysis().retained_summary();
            if let Some(positions) = &self.file_evidence_positions {
                summary.file_ios = positions.len() as u64;
                summary.attributed_file_ios = positions
                    .iter()
                    .filter(|&&i| {
                        matches!(
                            self.analysis().file_ios()[i].confidence,
                            android_ebpf_protocol::AttributionConfidence::Attributed
                                | android_ebpf_protocol::AttributionConfidence::Exact
                        )
                    })
                    .count() as u64;
            }
            self.performance.observe_summary_rebuild(started.elapsed());
            self.summary_view = Some((self.analysis_generation, Instant::now(), summary));
        }
        self.summary_view
            .as_ref()
            .expect("summary view is rebuilt")
            .2
            .clone()
    }

    fn metrics_ui(&mut self, ui: &mut egui::Ui) {
        let summary = self.analysis_summary();
        if summary.completed_ios == 0 {
            ui.label("No retained completed I/O detail. Per-request volume and latency are unavailable; check the separate kernel snapshot or device counters.");
            return;
        }
        ui.small("KPIs below use the same retained completed I/O and filters as the findings and graphs.");
        let completed = summary.completed_ios;
        let bytes_label = "READ / WRITE";
        let bytes_value = format!(
            "{} / {}",
            format_bytes(summary.read_bytes),
            format_bytes(summary.write_bytes)
        );
        let (p50, p95, p99) = (
            summary.p50_latency_ns,
            summary.p95_latency_ns,
            summary.p99_latency_ns,
        );
        ui.columns(3, |columns| {
            metric_card(
                &mut columns[0],
                "COMPLETED I/O",
                completed.to_string(),
                "requests",
                accent(),
            );
            metric_card(
                &mut columns[1],
                bytes_label,
                bytes_value,
                "transferred",
                green(),
            );
            metric_card(
                &mut columns[2],
                "P95 LATENCY",
                format_latency(p95),
                "insert/issue to completion",
                amber(),
            );
        });
        ui.add_space(8.0);
        ui.columns(3, |columns| {
            metric_card(
                &mut columns[0],
                "P50 LATENCY",
                format_latency(p50),
                "median · retained detail",
                green(),
            );
            metric_card(
                &mut columns[1],
                "P99 LATENCY",
                format_latency(p99),
                "tail · retained detail",
                red(),
            );
            metric_card(
                &mut columns[2],
                "MAX QUEUE DEPTH",
                summary
                    .max_queue_depth
                    .map_or("Not measured".into(), |n| n.to_string()),
                "in-flight requests",
                accent(),
            );
        });
    }

    fn rebuild_explorer_view(&mut self) {
        let started = Instant::now();
        let samples = self.analysis().completed_ios();
        let available = samples.len();
        let origin_ns = self.time_origin();
        let shows_storage_address =
            self.x_axis.is_storage_address() || self.y_axis.is_storage_address();
        let needs_graph = self.x_axis.needs_graph()
            || self.y_axis.needs_graph()
            || self.group_by.needs_graph()
            || shows_storage_address;
        let limit = if needs_graph {
            MAX_GRAPH_EXPLORER_POINTS
        } else {
            MAX_EXPLORER_POINTS
        };
        let mut groups: BTreeMap<String, Vec<ExplorerPoint>> = BTreeMap::new();
        for index in operation_sample_indices(samples, limit) {
            let io = &samples[index];
            let graph = needs_graph.then(|| self.analysis().transaction_for(io));
            let graph = graph.as_ref();
            let (Some(x), Some(y)) = (
                self.x_axis.value(io, origin_ns, graph),
                self.y_axis.value(io, origin_ns, graph),
            ) else {
                continue;
            };
            let file_tooltip = Some({
                graph.map_or_else(
                    || "File: <unattributed>".into(),
                    |graph| file_origin_tooltip(&block_file_origins(graph)),
                )
            });
            groups
                .entry(self.group_by.key(io, graph))
                .or_default()
                .push(ExplorerPoint {
                    coordinates: [x, y],
                    file_tooltip,
                    request: selection_key(io),
                });
        }
        let displayed = groups.values().map(Vec::len).sum();
        let mut groups: Vec<_> = groups.into_iter().collect();
        if groups.len() > MAX_EXPLORER_GROUPS {
            groups.sort_by_key(|group| std::cmp::Reverse(group.1.len()));
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
        self.performance.observe_explorer_rebuild(started.elapsed());
    }

    fn rebuild_pipeline_view(&mut self, io: CompletedIo) {
        let started = Instant::now();
        let pipeline = self.analysis().pipeline_for(&io);
        let graph = self.analysis().transaction_for(&io);
        let graph_metrics = graph.metrics();
        let origins = graph
            .nodes
            .iter()
            .find(|node| node.kind == IoNodeKind::BlockRequest)
            .map(|node| graph.file_origins_for(node.node_id))
            .unwrap_or_default();
        let slow_reason = self.analysis().why_slow(&io);
        self.pipeline_view = Some(PipelineView {
            generation: self.analysis_generation,
            io,
            pipeline,
            graph,
            graph_metrics,
            origins,
            slow_reason,
            built_at: Instant::now(),
        });
        self.performance.observe_pipeline_rebuild(started.elapsed());
    }

    fn explorer_ui(&mut self, ui: &mut egui::Ui) {
        let previous_axes = (self.x_axis, self.y_axis);
        ui.heading("Explore I/O");
        ui.scope(|ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("VIEW").size(10.0).strong().color(muted()));
                let previous = self.explorer_preset;
                egui::ComboBox::from_id_salt("explorer-preset")
                    .selected_text(self.explorer_preset.label())
                    .width(175.0)
                    .show_ui(ui, |ui| {
                        for preset in ExplorerPreset::ALL {
                            ui.selectable_value(&mut self.explorer_preset, preset, preset.label());
                        }
                    });
                if previous != self.explorer_preset
                    && let Some((x, y, group)) = self.explorer_preset.query()
                {
                    self.footprint.connected=self.explorer_preset==ExplorerPreset::ConnectedFootprint;
                    self.x_axis = x;
                    self.y_axis = y;
                    self.group_by = group;
                }
                ui.selectable_value(&mut self.selection.enabled, true, "Select");
                ui.selectable_value(&mut self.selection.enabled, false, "Pan");
                ui.label("Click / drag to select").on_hover_text("Select includes all plottable I/O in the area. Pan drags the view. The wheel zooms.");
            });
            if !matches!(self.y_axis,AxisMetric::Window(_)|AxisMetric::Timeline(_)|AxisMetric::SchedulerIoWait) {
            if !self.connected_footprint() {
            ui.horizontal_wrapped(|ui| {
                ui.label("Color Category");
                let previous_category = self.group_by;
                egui::ComboBox::from_id_salt("color-category")
                    .selected_text(self.group_by.label())
                    .width(170.0)
                    .show_ui(ui, |ui| {
                        for group in GroupBy::ALL {
                            ui.selectable_value(&mut self.group_by, group, group.label());
                        }
                    });
                if previous_category != self.group_by {
                    self.explorer_preset = ExplorerPreset::Custom;
                }
                ui.add(
                    egui::Slider::new(&mut self.plot_style.point_diameter, 2.0..=20.0)
                        .text("Point size (px)")
                        .step_by(0.5),
                );
            });
            }
            ui.collapsing("Advanced axes", |ui| {
                let before = (self.x_axis, self.y_axis, self.group_by);
                ui.horizontal_wrapped(|ui| {
                    axis_combo(ui, "x-axis", "X AXIS", &mut self.x_axis);
                    ui.add_space(8.0);
                    axis_combo(ui, "y-axis", "Y AXIS", &mut self.y_axis);
                    ui.add_space(8.0);
                });
                if before != (self.x_axis, self.y_axis, self.group_by) {
                    self.explorer_preset = ExplorerPreset::Custom;
                }
            });
            }
        });
        ui.add_space(10.0);

        if previous_axes != (self.x_axis, self.y_axis) {
            self.selection = SelectionState {
                enabled: true,
                auto_bounds: true,
                ..Default::default()
            };
        }
        self.footprint_controls(ui);
        if (self.footprint.mode != FootprintMode::Combined || self.connected_footprint())
            && self.x_axis == AxisMetric::TimeMs
            && matches!(self.y_axis, AxisMetric::Sector | AxisMetric::AddressKiB)
        {
            self.footprint_lanes_ui(ui);
            self.table_ui(ui);
        } else if self.y_axis == AxisMetric::SchedulerIoWait {
            self.scheduler_trend_ui(ui);
        } else if matches!(self.y_axis, AxisMetric::Timeline(_)) {
            self.timeline_ui(ui);
            self.table_ui(ui);
        } else if matches!(self.y_axis, AxisMetric::Window(_)) {
            self.window_series_ui(ui);
            self.table_ui(ui);
        } else {
            self.explorer_plot_ui(ui, false);
        }
    }

    fn explorer_plot_ui(&mut self, ui: &mut egui::Ui, compact: bool) -> Option<SelectionRequest> {
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
        let names = self
            .explorer_view
            .as_ref()
            .expect("explorer view is rebuilt")
            .groups
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        if !compact {
            self.axis_ranges_ui(ui);
            self.plot_colors_ui(ui, &names);
        }
        let legend_id = ui.make_persistent_id(("plot-legend", self.group_by.label()));
        let mut show_legend = ui.ctx().data_mut(|d| {
            d.get_temp::<bool>(legend_id).unwrap_or_else(|| {
                names.len() <= 6 && names.iter().all(|n| n.chars().count() <= 28)
            })
        });
        ui.horizontal_wrapped(|ui| {
            ui.checkbox(&mut show_legend, "Plot legend");
            if !show_legend {
                ui.small(format!(
                    "{} categories · full labels and colors in Colors above",
                    names.len()
                ));
            }
        });
        ui.ctx().data_mut(|d| d.insert_temp(legend_id, show_legend));
        let view = self
            .explorer_view
            .as_ref()
            .expect("explorer view is rebuilt");
        let point_radius = self.plot_style.point_diameter * 0.5;
        let x_axis = self.x_axis;
        let y_axis = self.y_axis;
        let mut selection_request = None;
        let mut drag_start = self.selection.drag_start;
        let selecting = self.selection.enabled;
        let bounds_command = self.selection.bounds_command.take();
        let auto_bounds = std::mem::take(&mut self.selection.auto_bounds);
        if view.displayed == 0 && !compact {
            ui.label("No plottable I/O for these axes and filters. Missing measurements are excluded; retained requests remain in the table below.");
        }
        let plot = studio_plot("interactive-storage-explorer");
        let plot = if show_legend {
            plot.legend(Legend::default())
        } else {
            plot
        };
        let plot_response = plot
            .allow_drag(!selecting)
            .allow_boxed_zoom(!selecting)
            // Outer scrolling must not increase the plot height and continually
            // push the event table farther away from the visible viewport.
            .height(if compact {
                220.0
            } else {
                (ui.ctx().content_rect().height() * 0.33).clamp(220.0, 500.0)
            })
            .x_axis_label(self.x_axis.label())
            .y_axis_label(self.y_axis.label())
            .label_formatter(|hover| match hover {
                HoverPosition::NearDataPoint {
                    plot_name,
                    position,
                    index,
                } => {
                    let point = view
                        .groups
                        .iter()
                        .find(|(name, _)| name == plot_name)
                        .and_then(|(_, points)| points.get(*index));
                    let mut label = format!(
                        "{plot_name}\n{}: {}\n{}: {}",
                        x_axis.label(),
                        x_axis.format_value(position.x),
                        y_axis.label(),
                        y_axis.format_value(position.y),
                    );
                    if let Some(file_tooltip) = point.and_then(|point| point.file_tooltip.as_ref())
                    {
                        label.push('\n');
                        label.push_str(file_tooltip);
                    }
                    Some(label)
                }
                HoverPosition::Elsewhere { .. } => None,
            })
            .show(ui, |plot| {
                if auto_bounds {
                    plot.set_auto_bounds(true);
                }
                if let Some(bounds) = bounds_command {
                    plot.set_plot_bounds(bounds);
                }
                self.render_qa.plot_rect = Some(plot.response().rect);
                self.render_qa.point_target = view
                    .groups
                    .iter()
                    .flat_map(|(_, p)| p)
                    .find(|p| {
                        p.file_tooltip
                            .as_ref()
                            .is_some_and(|v| v.contains("final-A.bin"))
                    })
                    .or_else(|| view.groups.iter().flat_map(|(_, points)| points).next())
                    .map(|p| {
                        plot.screen_from_plot(egui_plot::PlotPoint::new(
                            p.coordinates[0],
                            p.coordinates[1],
                        ))
                    });
                if selecting
                    && plot.response().clicked()
                    && let Some(pointer) = plot.pointer_coordinate()
                {
                    let screen = plot.screen_from_plot(pointer);
                    selection_request = view
                        .groups
                        .iter()
                        .flat_map(|(_, points)| points)
                        .filter_map(|point| {
                            let pos = plot.screen_from_plot(egui_plot::PlotPoint::new(
                                point.coordinates[0],
                                point.coordinates[1],
                            ));
                            let distance = pos.distance(screen);
                            (distance < 16.0).then_some((distance, point.request))
                        })
                        .min_by(|a, b| a.0.total_cmp(&b.0))
                        .map(|v| SelectionRequest::Point(v.1));
                }
                if selecting
                    && plot.response().drag_started()
                    && let Some(pos) = plot.response().interact_pointer_pos()
                {
                    let p = plot.plot_from_screen(pos - plot.response().drag_delta());
                    drag_start = Some([p.x, p.y]);
                }
                if selecting
                    && let Some(start) = drag_start
                    && let Some(pos) = plot.response().interact_pointer_pos()
                {
                    let p = plot.plot_from_screen(pos);
                    let min = [start[0].min(p.x), start[1].min(p.y)];
                    let max = [start[0].max(p.x), start[1].max(p.y)];
                    let rectangle: PlotPoints = vec![
                        [min[0], min[1]],
                        [max[0], min[1]],
                        [max[0], max[1]],
                        [min[0], max[1]],
                    ]
                    .into();
                    plot.polygon(
                        egui_plot::Polygon::new("Selection area", rectangle)
                            .fill_color(accent().gamma_multiply(0.15))
                            .stroke(Stroke::new(1.5, accent())),
                    );
                    if plot.response().drag_stopped() {
                        selection_request = Some(SelectionRequest::Rectangle { min, max });
                        drag_start = None;
                    }
                }
                for (name, values) in &view.groups {
                    let points: PlotPoints = values.iter().map(|point| point.coordinates).collect();
                    if let Some(summary) = &self.selection.summary {
                        let selected: PlotPoints = values
                            .iter()
                            .filter(|p| summary.keys.contains(&p.request))
                            .map(|p| p.coordinates)
                            .collect();
                        plot.points(
                            Points::new("Selected", selected)
                                .filled(false)
                                .allow_hover(false)
                                .radius(point_radius + 2.5)
                                .color(amber()),
                        );
                    }
                    plot.points(
                        Points::new(name.clone(), points)
                            .radius(point_radius)
                            .color(self.plot_style.color(self.group_by, name)),
                    );
                }
            });
        self.selection.drag_start = drag_start;
        self.selection.current_bounds = Some(*plot_response.transform.bounds());
        // Comparison plots are peers: data-dependent status belongs after the
        // plot so an empty population cannot shift only one graph down.
        if view.displayed == 0 && compact {
            ui.label("No plottable I/O for these axes and filters. Missing measurements are excluded; retained requests remain available in I/O details.");
        }
        if auto_bounds {
            self.selection
                .axis_range
                .read_view(*plot_response.transform.bounds());
        }
        if !compact && (self.x_axis.is_storage_address() || self.y_axis.is_storage_address()) {
            ui.label(
                RichText::new(
                    "Select a point or area for the right-hand summary. Hover reveals FilePath evidence; Investigate is available from the selection panel. The Completed I/O table provides the same file/LBA lookup without pointer hover.",
                )
                .small()
                .color(muted()),
            );
        }
        ui.label(
            RichText::new(format!(
                "Showing {} of {} completed I/O samples{}",
                view.displayed,
                view.available,
                if view.available > view.displayed {
                    " · sampled within each operation for interactive rendering"
                } else {
                    ""
                }
            ))
            .small()
            .color(muted()),
        );
        if let Some(request) = selection_request {
            self.begin_selection(request);
        }
        if self.render_qa.output.is_some()
            && std::env::var_os("ANDROID_EBPF_QA_SMALL").is_some()
            && std::env::var("ANDROID_EBPF_QA_GESTURE").as_deref() == Ok("zoom-back")
            && self.render_qa.input_step == 0
        {
            plot_response
                .response
                .scroll_to_me(Some(egui::Align::Center));
        }
        if !compact {
            self.table_ui(ui);
            ui.label(RichText::new("Queue latency requires block_rq_insert. Missing values are excluded instead of displayed as zero.").small().color(muted()));
        }
        selection_request
    }

    fn summary_breakdown_ui(&mut self, ui: &mut egui::Ui) {
        let summary = self.analysis_summary();

        section_header(
            ui,
            "Overview",
            "What happened, how trustworthy the capture is, and where to investigate next.",
        );
        if let Some(snapshot) = &self.latest_aggregate
            && !self.query.active()
        {
            card_frame().show(ui, |ui| {
                ui.label(
                    RichText::new(format!(
                        "Kernel aggregate · {} observed · {} detailed · {} fast suppressed",
                        snapshot.counters.observed,
                        snapshot.counters.detail_emitted,
                        snapshot.counters.suppressed_fast
                    ))
                    .color(green()),
                );
                ui.label(
                    RichText::new(
                        "Top KPIs use approximate histogram buckets; tables below describe retained detail.",
                    )
                    .small()
                    .color(muted()),
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
                summary.busy_ns.map_or("Not measured".into(), |busy| {
                    format!(
                        "{} ({:.1}%)",
                        format_duration(busy),
                        ratio(busy, summary.logging_ns)
                    )
                }),
            );
            summary_card(
                &mut columns[2],
                "Idle time",
                summary.idle_ns.map_or("Not measured".into(), |idle| {
                    format!(
                        "{} ({:.1}%)",
                        format_duration(idle),
                        ratio(idle, summary.logging_ns)
                    )
                }),
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
                .analysis()
                .completed_ios()
                .iter()
                .max_by_key(|request| request.total_latency_ns)
                .cloned()
            {
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new("SLOWEST RECENT REQUEST")
                            .size(10.0)
                            .color(muted()),
                    );
                    ui.label(
                        RichText::new(format!(
                            "#{} · {} · {} · {}",
                            slowest.issue.request_id,
                            operation_label(slowest.issue.operation),
                            format_bytes(slowest.issue.bytes as u64),
                            format_latency(slowest.total_latency_ns)
                        ))
                        .strong(),
                    );
                    if ui.button("Investigate").clicked() {
                        self.selected_pipeline_request = Some(selection_key(&slowest));
                        self.page = Page::Investigate;
                    }
                });
            } else {
                ui.label(RichText::new("No completed requests yet").color(muted()));
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
        if !self.heavy_hitters.is_empty() && !self.query.active() {
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
                            .color(muted()),
                        );
                        for entry in snapshot.entries.iter().take(10) {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(&entry.key).monospace().color(ink()));
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
        if !self.triggers.is_empty()
            || !self.segments.is_empty()
            || !self.stack_fingerprints.is_empty()
        {
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
                        .color(ink()),
                    );
                    ui.label(
                        RichText::new(format!(
                            "requested pre-window {} · actual pre-window {}",
                            format_duration(
                                segment
                                    .trigger_ts_ns
                                    .saturating_sub(segment.requested_start_ts_ns)
                            ),
                            format_duration(
                                segment
                                    .trigger_ts_ns
                                    .saturating_sub(segment.retained_start_ts_ns)
                            )
                        ))
                        .small()
                        .color(muted()),
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
        ui.small("Explain a selected request: queue wait, device time, and the evidence linking it to a file. Use Explore to compare many requests.");
        ui.add_space(10.0);

        ui.collapsing("Choose another request · newest 500", |ui| {
            ui.label(
                RichText::new("RECENT REQUESTS")
                    .size(10.0)
                    .strong()
                    .color(muted()),
            );
            let requests = self.analysis().completed_ios();
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
                                        selection == Some(selection_key(request)),
                                        format!("#{}", request.issue.request_id),
                                    )
                                    .clicked()
                                {
                                    selection = Some(selection_key(request));
                                }
                                ui.label(operation_label(request.issue.operation));
                                ui.label(format_bytes(request.issue.bytes as u64));
                                ui.label(format_latency(request.total_latency_ns));
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
                    .color(muted()),
                );
            }
            self.selected_pipeline_request = selection;
        });
        ui.add_space(10.0);

        let selected = self
            .selected_pipeline_request
            .and_then(|request_key| {
                self.analysis()
                    .completed_ios()
                    .iter()
                    .rev()
                    .find(|io| selection_key(io) == request_key)
            })
            .cloned()
            .or_else(|| {
                self.analysis()
                    .completed_ios()
                    .iter()
                    .max_by_key(|io| io.total_latency_ns)
                    .cloned()
            });
        let Some(io) = selected else {
            card_frame().show(ui, |ui| {
                ui.label(
                    RichText::new("No completed request yet")
                        .strong()
                        .color(ink()),
                );
                ui.label(
                    RichText::new(
                        "Record a session, then choose Explain this I/O in Overview or Open I/O in Explore. Device-counter-only sessions cannot show individual requests.",
                    )
                    .color(muted()),
                );
            });
            return;
        };
        ui.label(format!(
            "Focused I/O: {} · PID {} / TID {} · device {}:{}",
            io.issue.comm,
            identity_number(io.issuer_pid()),
            identity_number(io.issuer_tid()),
            io.issue.device_major,
            io.issue.device_minor
        ));
        ui.horizontal_wrapped(|ui| {
            ui.strong(format!("Total {}", format_latency(io.total_latency_ns)));
            ui.label(format!(
                "Queue wait {}",
                format_latency(io.queue_latency_ns)
            ));
            ui.label(format!(
                "Issue to completion {}",
                format_latency(io.device_latency_ns)
            ));
        });
        ui.small("Queue: insert to issue, when measured. The device/driver interval is issue to completion. No request chosen? This page starts with the slowest in the current filters.");
        if let Some(evidence) = &io.evidence {
            ui.heading("Perfetto block observation");
            ui.label(format!(
                "Timing: {:?} · {}",
                evidence.timing_confidence, evidence.reason
            ));
            ui.label(format!(
                "Raw completion record {} · issue candidates {:?}",
                evidence.record_id, evidence.issue_record_candidates
            ));
            ui.label(format!(
                "Issuer PID {} / TID {}",
                io.issuer_pid()
                    .map_or("unavailable".into(), |v| v.to_string()),
                io.issuer_tid()
                    .map_or("unavailable".into(), |v| v.to_string())
            ));
            if let Some(name) = &evidence.process_name {
                ui.label(format!("Process metadata candidate: {name}"));
            }
            ui.label("FilePath: Unresolved. Perfetto block tracepoints provide device/sector identity, not a file or inode mapping. Kernel request IDs and lower-layer cause attribution are unavailable.");
            ui.label(format!(
                "Device {}:{} · sector {} · {} · {}",
                io.issue.device_major,
                io.issue.device_minor,
                io.issue.sector,
                operation_label(io.issue.operation),
                format_bytes(io.issue.bytes as u64)
            ));
            if ui.button("Back to Explore").clicked() {
                self.page = Page::Explore;
            }
            return;
        }
        ui.horizontal_wrapped(|ui| {
            if ui.button("Explore this issuer").clicked() {
                self.open_finding(FindingAction::Issuer(io.issue.pid));
            }
            if ui.button("Back to Overview").clicked() {
                self.page = Page::Overview;
            }
        });
        self.selected_pipeline_request = Some(selection_key(&io));
        let cache_valid = self.pipeline_view.as_ref().is_some_and(|view| {
            (view.generation == self.analysis_generation
                || (self.is_running() && view.built_at.elapsed() < LIVE_ANALYSIS_REFRESH))
                && selection_key(&view.io) == selection_key(&io)
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
                ui.label(RichText::new("REQUEST").size(10.0).strong().color(muted()));
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
                    .color(green()),
                );
                ui.label(
                    RichText::new(format!(
                        "Unaccounted {}",
                        format_duration(pipeline.unaccounted_ns)
                    ))
                    .color(if pipeline.unaccounted_ns == 0 {
                        muted()
                    } else {
                        amber()
                    }),
                );
                ui.label(format!(
                    "Related graph critical path {} (can extend beyond this block request)",
                    format_duration(graph_metrics.critical_path_ns)
                ));
                if !graph_metrics.unaccounted.is_empty() {
                    ui.label(
                        RichText::new(format!(
                            "{} unaccounted interval(s): {:?}",
                            graph_metrics.unaccounted.len(),
                            graph_metrics.unaccounted[0].reason
                        ))
                        .color(amber()),
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
                    .color(muted()),
            );
            if origins.is_empty() {
                ui.label(RichText::new("Unattributed — no unique evidence").color(amber()));
            } else {
                for origin in &origins {
                    let label = origin
                        .path
                        .as_ref()
                        .and_then(|path| path.path.clone())
                        .unwrap_or_else(|| origin.file.fallback_label());
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new(label).monospace().color(ink()));
                        status_pill(
                            ui,
                            match path_confidence(std::slice::from_ref(origin)) {
                                PathConfidence::Exact => "Exact",
                                PathConfidence::Probable => "Probable",
                                PathConfidence::Unresolved => "Unresolved",
                            },
                            match path_confidence(std::slice::from_ref(origin)) {
                                PathConfidence::Exact => green(),
                                _ => amber(),
                            },
                        );
                    });
                }
            }
            if let Some(reason) = slow_reason {
                ui.separator();
                ui.label(
                    RichText::new("WHY SLOW?")
                        .size(10.0)
                        .strong()
                        .color(muted()),
                );
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
            studio_plot("pipeline-waterfall")
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
            ui.label(RichText::new("Drag to pan · wheel to zoom · double-click to reset. Nested bars are not summed; coverage uses interval union.").small().color(muted()));
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
                        ui.label(if span.duration_observed {
                            format_duration(span.duration_ns())
                        } else {
                            "Not measured".into()
                        });
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
                            (
                                "PID / TID",
                                format!(
                                    "{} / {}",
                                    identity_number(io.issuer_pid()),
                                    identity_number(io.issuer_tid())
                                ),
                            ),
                            ("Process", io.issue.comm.clone()),
                            ("Queue latency", format_latency(io.queue_latency_ns)),
                            ("Device latency", format_latency(io.device_latency_ns)),
                            ("Total latency", format_latency(io.total_latency_ns)),
                        ] {
                            ui.label(RichText::new(name).color(muted()));
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
            let files = self.analysis().file_ios();
            let positions:Vec<usize>=self.file_evidence_positions.clone().unwrap_or_else(||(0..files.len()).collect());
            let row_count = positions.len();
            ui.label(format!("{} file-operation records · {}",row_count,if self.file_evidence_positions.is_some(){"evidence for current filtered block requests; identity/time candidates, not extra exact block links"}else{"session file operations"}));
            egui::ScrollArea::vertical().show_rows(ui, 27.0, row_count, |ui, range| {
                egui::Grid::new("file-ios-rows")
                    .striped(true)
                    .spacing([16.0, 9.0])
                    .show(ui, |ui| {
                        for position in range {
                            let file = &files[positions[positions.len() - 1 - position]];
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

    fn table_ui(&mut self, ui: &mut egui::Ui) {
        section_header(
            ui,
            "Completed block I/O",
            "Current filters · all loaded detail rows · focus an Open button and press Enter for full I/O and FilePath evidence",
        );
        if ui.button("Export table I/O CSV").clicked() {
            self.export_io_cohort_csv(None);
        }
        let mut open = None;
        let mut table_focused = false;
        card_frame().show(ui, |ui| {
            let items = self.analysis().completed_ios();
            let title = ui.label(format!(
                "{} requests · newest first · rows render as you scroll",
                items.len()
            ));
            if self.render_qa.output.is_some()
                && std::env::var_os("ANDROID_EBPF_QA_TABLE_KEYBOARD").is_some()
                && self.render_qa.input_step == 0
            {
                title.scroll_to_me(Some(egui::Align::Min));
            }
            egui::ScrollArea::both()
                .id_salt("completed-io-table")
                .max_height(320.0)
                .show_rows(ui, 28.0, items.len() + 1, |ui, range| {
                    for position in range {
                        ui.horizontal(|ui| {
                            if position == 0 {
                                for (title, width) in [
                                    ("Details", 85.0),
                                    ("Time ns", 145.0),
                                    ("Op", 65.0),
                                    ("Access", 100.0),
                                    ("Bytes", 80.0),
                                    ("Sector", 110.0),
                                    ("Device", 85.0),
                                    ("Queue", 90.0),
                                    ("Device latency", 110.0),
                                    ("Total latency", 110.0),
                                    ("File / Origin", 260.0),
                                    ("Confidence", 100.0),
                                    ("PID / TID", 115.0),
                                    ("Process", 140.0),
                                ] {
                                    ui.add_sized(
                                        [width, 25.0],
                                        egui::Label::new(RichText::new(title).strong()),
                                    );
                                }
                                return;
                            }
                            let io = &items[items.len() - position];
                            let key = selection_key(io);
                            let response = ui
                                .push_id(key, |ui| {
                                    ui.add_sized([85.0, 25.0], egui::Button::new("Open I/O"))
                                })
                                .inner;
                            if self.render_qa.output.is_some()
                                && std::env::var_os("ANDROID_EBPF_QA_TABLE_KEYBOARD").is_some()
                                && position == 1
                                && self.render_qa.input_step == 0
                            {
                                response.request_focus();
                                response.scroll_to_me(Some(egui::Align::Center));
                                table_focused = response.has_focus();
                            }
                            if response.clicked() {
                                open = Some(key);
                            }
                            let graph = self.analysis().transaction_for(io);
                            let origins = block_file_origins(&graph);
                            let file = if origins.is_empty() {
                                "Unresolved · see I/O details".into()
                            } else if origins.len() > 1 {
                                format!("{} candidates · see I/O details", origins.len())
                            } else {
                                origins[0]
                                    .path
                                    .as_ref()
                                    .and_then(|p| p.path.clone())
                                    .unwrap_or_else(|| origins[0].file.fallback_label())
                            };
                            for (value, width) in [
                                (io.completion.ts_ns.to_string(), 145.0),
                                (operation_label(io.issue.operation).into(), 65.0),
                                (access_label(io.access_pattern).into(), 100.0),
                                (io.issue.bytes.to_string(), 80.0),
                                (io.issue.sector.to_string(), 110.0),
                                (
                                    format!("{}:{}", io.issue.device_major, io.issue.device_minor),
                                    85.0,
                                ),
                                (format_latency(io.queue_latency_ns), 90.0),
                                (format_latency(io.device_latency_ns), 110.0),
                                (format_latency(io.total_latency_ns), 110.0),
                                (file, 260.0),
                                (format!("{:?}", path_confidence(&origins)), 100.0),
                                (
                                    format!(
                                        "{} / {}",
                                        identity_number(io.issuer_pid()),
                                        identity_number(io.issuer_tid())
                                    ),
                                    115.0,
                                ),
                                (io.issue.comm.clone(), 140.0),
                            ] {
                                ui.add_sized([width, 25.0], egui::Label::new(&value).truncate())
                                    .on_hover_text(value);
                            }
                        });
                    }
                });
        });
        self.render_qa.table_button_focused |= table_focused;
        if let Some(key) = open {
            self.selected_pipeline_request = Some(key);
            self.page = Page::Investigate;
        }
    }

    fn compare_totals_ui(&mut self, ui: &mut egui::Ui) {
        section_header(
            ui,
            "Compare sessions",
            "Measure the current capture against a separately loaded baseline without replacing it.",
        );
        card_frame().show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                let pin = ui.add_enabled(
                    !self.is_running()
                        && !self.query.active()
                        && !self.analyzer.completed_ios().is_empty(),
                    egui::Button::new("Keep current as baseline"),
                );
                self.render_qa
                    .inspector_buttons
                    .insert("Keep baseline".into(), pin.rect.center());
                if pin.clicked() {
                    self.pin_comparison();
                }
                if ui.button("Open baseline session").clicked() {
                    self.open_comparison_session();
                }
                if self.comparison.is_some() && ui.button("Clear baseline").clicked() {
                    self.comparison = None;
                }
                ui.label(
                    RichText::new("Delta = Current − Baseline; lower latency is normally better.")
                        .color(muted()),
                );
            });
        });
        ui.add_space(10.0);

        if self.query.active() {
            ui.label("Comparison uses complete retained session detail. Clear request filters before comparing with a whole-session baseline.");
            if ui.button("Use full session for comparison").clicked() {
                self.query = AnalysisFilter::default();
                self.invalidate_query();
                self.rebuild_filtered();
            }
            return;
        }
        let Some(baseline) = self.comparison.as_ref() else {
            card_frame().show(ui, |ui| {
                ui.label(RichText::new("No baseline loaded").strong());
                ui.label(
                    RichText::new(
                        "Keep this run as the baseline, then record or open your next run. Compare latency and transferred bytes to check a workload or configuration change. You can also open an earlier baseline file.",
                    )
                    .color(muted()),
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
                    .color(muted()),
                );
            });
            return;
        }
        if current.completed_ios == 0 && current.file_ios == 0 {
            card_frame().show(ui, |ui| {
                ui.label(RichText::new("Current session has no analyzable I/O").strong());
                ui.label(
                    RichText::new("Open or record the current session before calculating deltas.")
                        .color(muted()),
                );
            });
            return;
        }

        ui.label("Compare equivalent workloads and recording durations; a different request mix does not prove a device or app improvement.");
        if let Some((before, after)) = baseline_summary.p95_latency_ns.zip(current.p95_latency_ns) {
            ui.strong(format!(
                "P95 latency: {}",
                relative_delta_percent(before, after).map_or(
                    "percentage unavailable (zero baseline)".into(),
                    |v| format!("{v:+.1}% versus baseline")
                )
            ));
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
                    ui.label("Max queue depth");
                    for value in [baseline_summary.max_queue_depth, current.max_queue_depth] {
                        ui.label(value.map_or("Not measured".into(), |n| n.to_string()));
                    }
                    ui.label(
                        baseline_summary
                            .max_queue_depth
                            .zip(current.max_queue_depth)
                            .map_or("—".into(), |(a, b)| {
                                format!("{:+}", b as i128 - a as i128)
                            }),
                    );
                    ui.end_row();
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
        self.capture_quality_ui(ui);
        section_header(
            ui,
            "Diagnostic records",
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
        ui.add_space(10.0);
        let performance = self.performance.snapshot();
        let mut reset_performance = false;
        card_frame().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("UI PERFORMANCE")
                        .size(10.0)
                        .strong()
                        .color(muted()),
                );
                ui.with_layout(
                    egui::Layout::right_to_left(egui::Align::Center),
                    |ui| {
                        if ui.button("Reset measurements").clicked() {
                            reset_performance = true;
                        }
                    },
                );
            });
            ui.label(
                RichText::new(
                    "CPU time spent building each UI update; this excludes GPU presentation time.",
                )
                .small()
                .color(muted()),
            );
            ui.add_space(8.0);
            egui::Grid::new("ui-performance-grid")
                .striped(true)
                .spacing([18.0, 7.0])
                .show(ui, |ui| {
                    for heading in ["Path", "Samples", "p50", "p95", "Max", "Over budget"] {
                        ui.strong(heading);
                    }
                    ui.end_row();
                    performance_metric_row(ui, "UI update", &performance.ui_update);
                    performance_metric_row(ui, "Message drain", &performance.message_drain);
                    performance_metric_row(ui, "Summary rebuild", &performance.summary_rebuild);
                    performance_metric_row(ui, "Explorer rebuild", &performance.explorer_rebuild);
                    performance_metric_row(ui, "Pipeline rebuild", &performance.pipeline_rebuild);
                });
            ui.add_space(6.0);
            ui.label(format!(
                "Host-message backlog: {} current · {} peak",
                performance.current_backlog, performance.peak_backlog
            ));
            if let Some(aggregate) = &self.latest_aggregate {
                let selected = aggregate
                    .counters
                    .detail_emitted
                    .saturating_add(aggregate.counters.suppressed_fast);
                let suppression = if selected == 0 {
                    0.0
                } else {
                    aggregate.counters.suppressed_fast as f64 * 100.0 / selected as f64
                };
                ui.label(format!(
                    "Capture efficiency: observed {} · detail {} · fast suppressed {} ({suppression:.1}%) · ring failures {}",
                    aggregate.counters.observed,
                    aggregate.counters.detail_emitted,
                    aggregate.counters.suppressed_fast,
                    aggregate.counters.ring_reserve_failures,
                ));
            }
        });
        if reset_performance {
            self.performance.reset();
            self.last_performance_warning = Instant::now();
        }
        if let Some(capabilities) = &self.capabilities {
            ui.add_space(10.0);
            card_frame().show(ui, |ui| {
                ui.label(
                    RichText::new("PROBE STATUS")
                        .size(10.0)
                        .strong()
                        .color(muted()),
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
    fn persist_egui_memory(&self) -> bool {
        self.render_qa.output.is_none()
    }
    fn raw_input_hook(&mut self, _ctx: &egui::Context, raw: &mut egui::RawInput) {
        self.qa_input(raw);
    }
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        if self.render_qa.output.is_none() {
            eframe::set_value(storage, "theme", &self.theme);
            eframe::set_value(storage, "plot-style-v1", &self.plot_style);
            eframe::set_value(storage, "plot-color-category-v1", &self.group_by);
        }
    }
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ui_started = Instant::now();
        self.drain_messages();
        if ui.ctx().input(|i| i.viewport().close_requested()) && self.is_running() {
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.close_after_capture = true;
            self.stop();
        }
        if self.close_after_capture && !self.is_running() {
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
        }
        if !self.rx.is_empty() {
            ui.ctx().request_repaint();
        } else if self.is_running() {
            ui.ctx().request_repaint_after(Duration::from_millis(33));
        }
        if !self.is_running()
            && self
                .last_discovery
                .is_none_or(|v| v.elapsed() > Duration::from_secs(3))
        {
            self.refresh();
        }
        ui.ctx().request_repaint_after(Duration::from_millis(250));
        apply_theme(ui.ctx(), self.theme);
        let compact = ui.ctx().content_rect().width() < 1100.0;

        self.render_qa.regions.clear();
        self.header_ui(ui, compact);

        if !compact {
            egui::Panel::left("navigation")
                .exact_size(244.0)
                .resizable(false)
                .frame(
                    egui::Frame::new()
                        .fill(panel())
                        .inner_margin(egui::Margin::same(16))
                        .stroke(Stroke::new(1.0, border())),
                )
                .show(ui, |ui| {
                    egui::ScrollArea::vertical()
                        .id_salt("navigation-scroll")
                        .show(ui, |ui| {
                            ui.label(
                                RichText::new("TARGET DEVICE")
                                    .size(10.0)
                                    .strong()
                                    .color(muted()),
                            );
                            ui.add_space(7.0);
                            ui.add_enabled_ui(!self.is_running(), |ui| {
                                let before = self.selected_serial.clone();
                                egui::ComboBox::from_id_salt("device")
                                    .selected_text(
                                        self.selected_serial
                                            .as_deref()
                                            .unwrap_or("No device selected"),
                                    )
                                    .width(210.0)
                                    .show_ui(ui, |ui| {
                                        for device in self
                                            .devices
                                            .iter()
                                            .filter(|d| d.state == DeviceState::Device)
                                        {
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
                                if before != self.selected_serial {
                                    self.preflight = None;
                                }
                            });
                            ui.add_space(8.0);
                            if ui
                                .add_sized(
                                    [210.0, 34.0],
                                    egui::Button::new("↻  Refresh ADB devices"),
                                )
                                .clicked()
                            {
                                self.refresh();
                            }
                            ui.label("Start automatically detects root and tracking support.");
                            ui.add_space(16.0);
                            ui.label(RichText::new("ANALYSIS").size(10.0).strong().color(muted()));
                            ui.add_space(6.0);
                            nav_item(
                                ui,
                                &mut self.page,
                                Page::Overview,
                                "▦",
                                "Overview",
                                "What matters in this run",
                            );
                            nav_item(
                                ui,
                                &mut self.page,
                                Page::Investigate,
                                "⇢",
                                "Investigate",
                                "Explain one I/O",
                            );
                            nav_item(
                                ui,
                                &mut self.page,
                                Page::Explore,
                                "⌁",
                                "Explore",
                                "Narrow down patterns",
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
                            ui.label(
                                RichText::new("OPERATIONS")
                                    .size(10.0)
                                    .strong()
                                    .color(muted()),
                            );
                            ui.add_space(4.0);
                            nav_item(
                                ui,
                                &mut self.page,
                                Page::Diagnostics,
                                "⚙",
                                "Diagnostics",
                                "Trust, loss and capture errors",
                            );

                            ui.add_space(12.0);
                            ui.collapsing("Advanced capture settings", |ui| {
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new("LOG LEVEL").size(10.0).color(muted()));
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
                                        ui.add(
                                            egui::DragValue::new(&mut self.filter_pid)
                                                .range(0..=u32::MAX),
                                        );
                                    });
                                    egui::ComboBox::from_id_salt("filter-operation")
                                        .selected_text(
                                            self.filter_operation
                                                .map_or("All operations".into(), |value| {
                                                    format!("{value:?}")
                                                }),
                                        )
                                        .width(190.0)
                                        .show_ui(ui, |ui| {
                                            ui.selectable_value(
                                                &mut self.filter_operation,
                                                None,
                                                "All operations",
                                            );
                                            for operation in [IoOperation::Read, IoOperation::Write]
                                            {
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
                                            .color(muted()),
                                    );
                                    if self.capture_mode == CaptureMode::RawAll {
                                        ui.label(
                                            RichText::new(
                                                "RawAll can generate high event and UI load",
                                            )
                                            .size(10.0)
                                            .color(amber()),
                                        );
                                    }
                                });

                                if ui
                                    .add_enabled(
                                        !self.is_running(),
                                        egui::Button::new("Run simulator (synthetic)"),
                                    )
                                    .clicked()
                                {
                                    self.start_simulator();
                                }
                                if ui
                                    .add_enabled(
                                        !self.is_running() && self.selected_serial.is_some(),
                                        egui::Button::new("Inspect capabilities"),
                                    )
                                    .clicked()
                                {
                                    self.preflight();
                                }
                            });
                            ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                                ui.label(
                                    RichText::new(format!(
                                        "{} received  •  {} rejected",
                                        self.received_events, self.rejected_records
                                    ))
                                    .size(10.0)
                                    .color(muted()),
                                );
                                if let Some(path) = &self.session_path {
                                    ui.label(
                                        RichText::new(
                                            path.file_name()
                                                .and_then(|v| v.to_str())
                                                .unwrap_or("session.ndjson"),
                                        )
                                        .size(10.0)
                                        .color(muted()),
                                    );
                                }
                            });
                        });
                });
        }

        egui::Panel::bottom("diagnostics")
            .frame(
                egui::Frame::new()
                    .fill(panel())
                    .inner_margin(egui::Margin::symmetric(18, 8))
                    .stroke(Stroke::new(1.0, border())),
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
                                            DiagnosticLevel::Error => red(),
                                            DiagnosticLevel::Warn => amber(),
                                            _ => muted(),
                                        },
                                    ),
                                );
                            }
                        });
                });
            });

        if self.page == Page::Explore
            && !matches!(self.phase, CapturePhase::Stopping | CapturePhase::Analyzing)
        {
            self.rebuild_filtered();
            self.selection_panel(ui);
        }
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(bg())
                    .inner_margin(egui::Margin::same(14)),
            )
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt(format!(
                        "analysis-page-{:?}-{:?}",
                        self.page,
                        if self.page == Page::Investigate {
                            self.selected_pipeline_request
                        } else {
                            None
                        }
                    ))
                    .show(ui, |ui| {
                        self.analysis_page_ui(ui);
                    });
            });
        self.render_qa_tick(ui.ctx());
        self.performance.observe_ui_update(ui_started.elapsed());
        self.maybe_emit_performance_warning();
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
enum ThemeChoice {
    #[default]
    System,
    Light,
    Dark,
    HighContrast,
}
thread_local! { static ACTIVE_THEME: std::cell::Cell<ThemeChoice> = const { std::cell::Cell::new(ThemeChoice::Dark) }; }
fn palette_color(index: usize, dark: Color32) -> Color32 {
    ACTIVE_THEME.with(|theme| match theme.get() {
        ThemeChoice::Light => [
            Color32::from_rgb(246, 248, 251),
            Color32::WHITE,
            Color32::from_rgb(232, 237, 244),
            Color32::from_rgb(172, 184, 203),
            Color32::from_rgb(20, 30, 45),
            Color32::from_rgb(68, 82, 104),
            Color32::from_rgb(25, 86, 183),
            Color32::from_rgb(0, 112, 72),
            Color32::from_rgb(143, 82, 0),
            Color32::from_rgb(180, 32, 51),
        ][index],
        ThemeChoice::HighContrast => [
            Color32::BLACK,
            Color32::BLACK,
            Color32::BLACK,
            Color32::WHITE,
            Color32::WHITE,
            Color32::WHITE,
            Color32::from_rgb(90, 190, 255),
            Color32::from_rgb(95, 255, 150),
            Color32::YELLOW,
            Color32::from_rgb(255, 130, 140),
        ][index],
        _ => dark,
    })
}
fn apply_theme(ctx: &egui::Context, choice: ThemeChoice) {
    let resolved = if choice == ThemeChoice::System {
        if ctx.input(|i| i.raw.system_theme) == Some(egui::Theme::Light) {
            ThemeChoice::Light
        } else {
            ThemeChoice::Dark
        }
    } else {
        choice
    };
    ACTIVE_THEME.with(|theme| theme.set(resolved));
    let mut visuals = if resolved == ThemeChoice::Light {
        egui::Visuals::light()
    } else {
        egui::Visuals::dark()
    };
    visuals.panel_fill = bg();
    visuals.window_fill = panel();
    visuals.extreme_bg_color = bg();
    visuals.faint_bg_color = panel_raised();
    visuals.override_text_color = Some(ink());
    visuals.selection.bg_fill = panel_raised();
    visuals.selection.stroke = Stroke::new(2.0, accent());
    visuals.widgets.inactive.bg_fill = panel_raised();
    visuals.widgets.inactive.weak_bg_fill = panel_raised();
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, ink());
    visuals.widgets.hovered.bg_fill = panel_raised();
    visuals.widgets.hovered.fg_stroke = Stroke::new(2.0, accent());
    visuals.widgets.active.bg_fill = panel_raised();
    visuals.widgets.active.fg_stroke = Stroke::new(2.0, accent());
    ctx.set_visuals(visuals);
    ctx.global_style_mut(|style| {
        style.spacing.item_spacing = egui::vec2(8.0, 5.0);
        style.spacing.button_padding = egui::vec2(9.0, 5.0);
        style.spacing.interact_size.y = 26.0;
    });
}

fn card_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(panel())
        .stroke(Stroke::new(1.0, border()))
        .corner_radius(10)
        .inner_margin(egui::Margin::same(16))
}

fn section_header(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    ui.label(RichText::new(title).size(20.0).strong().color(ink()));
    ui.label(RichText::new(subtitle).size(11.0).color(muted()));
    ui.add_space(10.0);
}

fn metric_card(ui: &mut egui::Ui, label: &str, value: String, hint: &str, color: Color32) {
    card_frame().show(ui, |ui| {
        ui.label(RichText::new(label).size(10.0).strong().color(muted()));
        ui.add_space(5.0);
        ui.label(RichText::new(value).size(22.0).strong().color(color));
        ui.label(RichText::new(hint).size(10.0).color(muted()));
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
            ui.label(RichText::new(text).size(11.0).color(color));
        });
}

#[allow(dead_code)]
fn workflow_step(ui: &mut egui::Ui, number: usize, label: &str, active: bool, done: bool) {
    let color = if done {
        green()
    } else if active {
        accent()
    } else {
        muted()
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
                .color(if active || done { ink() } else { muted() }),
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
            panel_raised()
        } else {
            Color32::TRANSPARENT
        })
        .corner_radius(7)
        .inner_margin(egui::Margin::symmetric(10, 8))
        .show(ui, |ui| {
            ui.set_min_width(190.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new(icon).size(18.0).color(if selected {
                    accent()
                } else {
                    muted()
                }));
                ui.vertical(|ui| {
                    ui.label(RichText::new(title).strong().color(if selected {
                        ink()
                    } else {
                        muted()
                    }));
                    ui.label(RichText::new(detail).size(9.0).color(muted()));
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
        .fill(panel_raised())
        .stroke(Stroke::new(1.0, accent()))
        .corner_radius(6)
        .inner_margin(egui::Margin::same(10))
        .show(ui, |ui| {
            ui.label(RichText::new(format!("ⓘ  {text}")).size(11.0).color(ink()));
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
            .color(muted()),
        );
    });
}

fn capability_badge(ui: &mut egui::Ui, label: &str, available: bool) {
    let color = if available { green() } else { red() };
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
            ui.label(RichText::new("Unavailable").color(muted()));
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
    let color = match value {
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
    };
    ACTIVE_THEME.with(|theme| {
        if theme.get() == ThemeChoice::Light {
            Color32::from_rgb(color.r() / 2, color.g() / 2, color.b() / 2)
        } else {
            color
        }
    })
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
    let nodes: Vec<_> = graph
        .nodes
        .iter()
        .filter(|node| node.kind == kind)
        .collect();
    if nodes.is_empty() {
        return None;
    }
    let duration = nodes.iter().try_fold(0u64, |total, node| {
        total.checked_add(node.end_ts_ns?.checked_sub(node.start_ts_ns)?)
    })?;
    Some(duration as f64 / 1e6)
}

fn block_file_origins(graph: &IoTransactionGraph) -> Vec<FileOriginView> {
    graph
        .nodes
        .iter()
        .find(|node| node.kind == IoNodeKind::BlockRequest)
        .map(|node| graph.file_origins_for(node.node_id))
        .unwrap_or_default()
}

fn file_origin_tooltip(origins: &[FileOriginView]) -> String {
    if origins.is_empty() {
        return "File: <unattributed>\nReason: no observed file identity or defensible file correlation for this request".into();
    }

    let mut lines = Vec::with_capacity(origins.len().min(4) + 2);
    lines.push(if origins.len() == 1 {
        "File:".into()
    } else {
        format!("Files ({}):", origins.len())
    });
    for origin in origins.iter().take(4) {
        let path = origin
            .path
            .as_ref()
            .and_then(|snapshot| snapshot.path.as_deref())
            .filter(|path| !path.is_empty())
            .map(|path| path.replace(['\r', '\n'], " "))
            .unwrap_or_else(|| {
                format!(
                    "<path unresolved> · {} · no matching path snapshot",
                    origin.file.fallback_label()
                )
            });
        lines.push(format!(
            "  {path} [{}]",
            edge_confidence_label(origin.confidence)
        ));
    }
    if origins.len() > 4 {
        lines.push(format!("  +{} more", origins.len() - 4));
    }
    lines.join("\n")
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
        ui.label(RichText::new(label).size(10.0).color(muted()));
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
                .color(muted()),
        );
        ui.add_space(5.0);
        ui.label(RichText::new(value).size(20.0).strong().color(ink()));
    });
}

fn performance_metric_row(ui: &mut egui::Ui, label: &str, value: &LatencySnapshot) {
    ui.label(label);
    ui.label(value.samples.to_string());
    ui.label(format!("{:.3} ms", value.p50_ms));
    ui.label(format!("{:.3} ms", value.p95_ms));
    ui.label(format!("{:.3} ms", value.max_ms));
    ui.label(value.over_budget.to_string());
    ui.end_row();
}

#[cfg(test)]
mod ui_tests {
    use super::*;
    use android_ebpf_protocol::{FileIdentity, PathSnapshot, PathSource};

    #[test]
    fn failed_capture_does_not_leave_capturing_status() {
        let mut app = StudioApp {
            status: "Capturing eBPF storage events".into(),
            ..StudioApp::default()
        };
        app.tx
            .send(HostMessage::Ended(Err("root required".into())))
            .unwrap();
        app.drain_messages();
        assert_eq!(app.phase, CapturePhase::Error);
        assert!(app.status.contains("root required"));
        assert!(app.capture.is_none());
    }

    #[test]
    #[ignore = "requires ANDROID_EBPF_ACCEPTANCE_SESSION from the physical-device workload"]
    fn device_capture_replays_into_correct_lba_file_tooltips() {
        let path = std::env::var("ANDROID_EBPF_ACCEPTANCE_SESSION").expect("capture path");
        let input = std::fs::read_to_string(path).unwrap();
        let mut app = StudioApp::default();
        let mut expected = BTreeMap::new();
        for line in input.lines().filter(|line| !line.trim().is_empty()) {
            let record: android_ebpf_protocol::WireRecord = serde_json::from_str(line).unwrap();
            if let android_ebpf_protocol::WireRecord::Event { event, .. } = record {
                if let android_ebpf_protocol::StorageEvent::RequestOrigin(origin) = &event
                    && origin.operation == IoOperation::Read
                    && let Some(path) = origin
                        .path
                        .as_ref()
                        .and_then(|snapshot| snapshot.path.as_ref())
                    && (path.ends_with("/final-A.bin") || path.ends_with("/final-B.bin"))
                {
                    expected.insert(origin.request_id, path.clone());
                }
                app.analyzer.ingest(event);
            }
        }
        assert_eq!(expected.len(), 128, "64 reads per known file");
        let mut verified = 0;
        for io in app.analyzer.completed_ios() {
            if let Some(path) = expected.get(&io.issue.request_id) {
                let graph = app.analyzer.transaction_for(io);
                let origins = block_file_origins(&graph);
                assert_eq!(origins.len(), 1, "one known file per read request");
                assert_eq!(
                    origins[0]
                        .path
                        .as_ref()
                        .and_then(|snapshot| snapshot.path.as_ref()),
                    Some(path)
                );
                assert!(file_origin_tooltip(&origins).contains(path));
                verified += 1;
            }
        }
        assert_eq!(
            verified, 128,
            "every read is completed and has the correct tooltip"
        );
        app.x_axis = AxisMetric::TimeMs;
        app.y_axis = AxisMetric::Sector;
        app.rebuild_explorer_view();
        let view = app.explorer_view.as_ref().unwrap();
        for suffix in ["/final-A.bin", "/final-B.bin"] {
            assert!(
                view.groups
                    .iter()
                    .flat_map(|(_, points)| points)
                    .filter(|point| point
                        .file_tooltip
                        .as_ref()
                        .is_some_and(|tip| tip.contains(suffix)))
                    .count()
                    >= 64
            );
        }
    }

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
    fn lba_hover_tooltip_shows_path_confidence_and_identity_fallback() {
        let attributed = FileOriginView {
            file: FileIdentity {
                fs_device_major: 254,
                fs_device_minor: 11,
                inode: 93844,
                inode_generation: None,
                mount_id: None,
            },
            path: Some(PathSnapshot {
                path: Some("/data/local/tmp/test.bin".into()),
                source: PathSource::ProcFd,
                captured_ts_ns: 100,
                deleted: false,
            }),
            confidence: EdgeConfidence::Exact,
        };
        assert_eq!(
            file_origin_tooltip(std::slice::from_ref(&attributed)),
            "File:\n  /data/local/tmp/test.bin [Exact]"
        );

        let unresolved = FileOriginView {
            path: None,
            confidence: EdgeConfidence::Probable,
            ..attributed
        };
        let tooltip = file_origin_tooltip(&[unresolved]);
        assert!(tooltip.contains("<path unresolved>"));
        assert!(tooltip.contains("254:11"));
        assert!(tooltip.contains("93844"));
        assert!(tooltip.contains("[Probable]"));
        assert!(AxisMetric::Sector.is_storage_address());
        assert!(AxisMetric::AddressKiB.is_storage_address());
        assert!(!AxisMetric::TimeMs.is_storage_address());
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
