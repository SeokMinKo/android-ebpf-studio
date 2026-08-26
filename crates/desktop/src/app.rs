use std::{
    collections::{BTreeMap, VecDeque},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use android_ebpf_protocol::{
    AccessPattern, AnalysisEngine, CompletedIo, IoOperation, IoSizeClass, SCHEMA_VERSION,
    WireRecord,
};
use crossbeam_channel::{Receiver, Sender, bounded};
use eframe::egui::{self, Color32, RichText};
use egui_plot::{Legend, Plot, PlotPoints, Points};

use crate::{
    adb::{AdbClient, AdbDevice, DeviceState, PreflightReport},
    capture::{self, CaptureHandle, HostMessage},
    session::{self, SessionWriter},
    simulator,
};

const MAX_RECENT: usize = 2_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Page {
    Summary,
    Explorer,
    Events,
    Files,
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
}

impl AxisMetric {
    const ALL: [Self; 9] = [
        Self::TimeMs,
        Self::Sector,
        Self::AddressKiB,
        Self::ChunkKiB,
        Self::TotalLatencyMs,
        Self::QueueLatencyMs,
        Self::DeviceLatencyMs,
        Self::Pid,
        Self::QueueDepth,
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
        }
    }

    fn value(self, io: &CompletedIo, origin_ns: u64) -> Option<f64> {
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
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GroupBy {
    None,
    Direction,
    AccessPattern,
    SizeClass,
    Process,
}

impl GroupBy {
    const ALL: [Self; 5] = [
        Self::None,
        Self::Direction,
        Self::AccessPattern,
        Self::SizeClass,
        Self::Process,
    ];
    fn label(self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Direction => "Read / Write",
            Self::AccessPattern => "Sequential / Random",
            Self::SizeClass => "Small / Large",
            Self::Process => "Process",
        }
    }
    fn key(self, io: &CompletedIo) -> String {
        match self {
            Self::None => "All I/O".into(),
            Self::Direction => operation_label(io.issue.operation).into(),
            Self::AccessPattern => access_label(io.access_pattern).into(),
            Self::SizeClass => size_label(io.size_class).into(),
            Self::Process => format!("{} ({})", io.issue.comm, io.issue.pid),
        }
    }
}

pub struct StudioApp {
    adb: AdbClient,
    tx: Sender<HostMessage>,
    rx: Receiver<HostMessage>,
    devices: Vec<AdbDevice>,
    selected_serial: Option<String>,
    preflight: Option<PreflightReport>,
    status: String,
    diagnostics: VecDeque<String>,
    analyzer: AnalysisEngine,
    recent: VecDeque<CompletedIo>,
    capture: Option<CaptureHandle>,
    simulator_stop: Option<Arc<AtomicBool>>,
    writer: Option<SessionWriter>,
    session_path: Option<PathBuf>,
    received_events: u64,
    rejected_records: u64,
    page: Page,
    x_axis: AxisMetric,
    y_axis: AxisMetric,
    group_by: GroupBy,
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
            received_events: 0,
            rejected_records: 0,
            page: Page::Summary,
            x_axis: AxisMetric::TimeMs,
            y_axis: AxisMetric::TotalLatencyMs,
            group_by: GroupBy::Direction,
        }
    }
}

impl StudioApp {
    fn refresh(&mut self) {
        self.status = "Refreshing ADB devices…".into();
        capture::refresh_devices(self.adb.clone(), self.tx.clone());
    }

    fn preflight(&mut self) {
        if let Some(serial) = self.selected_serial.clone() {
            capture::run_preflight(self.adb.clone(), serial, self.tx.clone());
        }
    }

    fn select_session_path(&mut self) -> bool {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("NDJSON session", &["ndjson"])
            .set_file_name("android-storage-session.ndjson")
            .save_file()
        else {
            return false;
        };
        match SessionWriter::create(&path) {
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
        let Some(agent) = rfd::FileDialog::new()
            .set_title("Select Android arm64 agent")
            .pick_file()
        else {
            return;
        };
        let Some(bpf) = rfd::FileDialog::new()
            .add_filter("eBPF object", &["o"])
            .set_title("Select storage eBPF object")
            .pick_file()
        else {
            return;
        };
        if !self.select_session_path() {
            return;
        }
        self.reset_analysis();
        self.capture = Some(capture::start_adb(
            self.adb.clone(),
            serial,
            agent,
            bpf,
            self.tx.clone(),
        ));
    }

    fn start_simulator(&mut self) {
        if !self.select_session_path() {
            return;
        }
        self.reset_analysis();
        let stop = Arc::new(AtomicBool::new(false));
        simulator::start(self.tx.clone(), stop.clone());
        self.simulator_stop = Some(stop);
    }

    fn stop(&mut self) {
        if let Some(handle) = self.capture.take() {
            handle.stop();
        }
        if let Some(stop) = self.simulator_stop.take() {
            stop.store(true, Ordering::Release);
        }
        self.finish_session();
        self.status = "Stopped".into();
    }

    fn finish_session(&mut self) {
        if let Some(writer) = self.writer.take() {
            let persisted = writer.persisted;
            let rejected = writer.rejected + self.rejected_records;
            let footer = WireRecord::Footer {
                schema_version: SCHEMA_VERSION,
                events_seen: self.received_events,
                events_persisted: persisted,
                events_dropped: self.received_events.saturating_sub(persisted + rejected),
                events_rejected: rejected,
            };
            if let Err(error) = writer.finish(&footer) {
                self.push_diagnostic(error.to_string());
            }
        }
    }

    fn open_session(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("NDJSON session", &["ndjson"])
            .pick_file()
        else {
            return;
        };
        match session::load_analysis(&path) {
            Ok((engine, rejected)) => {
                self.stop();
                self.recent = engine
                    .completed_ios()
                    .iter()
                    .rev()
                    .take(MAX_RECENT)
                    .cloned()
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
                self.analyzer = engine;
                self.rejected_records = rejected;
                self.session_path = Some(path);
                self.status = "Offline session loaded".into();
            }
            Err(error) => self.push_diagnostic(error.to_string()),
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
        match session::export_csv(&session_path, &path) {
            Ok(summary) => self.status = format!("Exported CSV and {}", summary.display()),
            Err(error) => self.push_diagnostic(error.to_string()),
        }
    }

    fn drain_messages(&mut self) {
        for _ in 0..5_000 {
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
                HostMessage::Diagnostic(value) => self.push_diagnostic(value),
                HostMessage::Ended(result) => {
                    if let Err(error) = result {
                        self.push_diagnostic(error);
                    }
                    self.finish_session();
                    self.capture = None;
                    self.simulator_stop = None;
                }
            }
        }
    }

    fn ingest_record(&mut self, record: WireRecord) {
        if let Some(writer) = self.writer.as_mut()
            && let Err(error) = writer.append(&record)
        {
            self.rejected_records += 1;
            self.push_diagnostic(error.to_string());
        }
        if let WireRecord::Event { event, .. } = record {
            self.received_events += 1;
            if let Some(completed) = self.analyzer.ingest(event) {
                if self.recent.len() == MAX_RECENT {
                    self.recent.pop_front();
                }
                self.recent.push_back(completed);
            }
        }
    }

    fn reset_analysis(&mut self) {
        self.analyzer = AnalysisEngine::new();
        self.recent.clear();
        self.received_events = 0;
        self.rejected_records = 0;
    }

    fn push_diagnostic(&mut self, value: String) {
        if self.diagnostics.len() == 200 {
            self.diagnostics.pop_front();
        }
        self.diagnostics.push_back(value);
    }

    fn metrics_ui(&self, ui: &mut egui::Ui) {
        let summary = self.analyzer.summary();
        ui.columns(6, |columns| {
            columns[0].label("Completed I/O");
            columns[0].heading(summary.completed_ios.to_string());
            columns[1].label("Read / Write");
            columns[1].heading(format!(
                "{} / {} MiB",
                summary.read_bytes / 1_048_576,
                summary.write_bytes / 1_048_576
            ));
            columns[2].label("p50 latency");
            columns[2].heading(format_latency(summary.p50_latency_ns));
            columns[3].label("p95 latency");
            columns[3].heading(format_latency(summary.p95_latency_ns));
            columns[4].label("p99 latency");
            columns[4].heading(format_latency(summary.p99_latency_ns));
            columns[5].label("Max queue depth");
            columns[5].heading(summary.max_queue_depth.to_string());
        });
    }

    fn explorer_ui(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            axis_combo(ui, "x-axis", "X axis", &mut self.x_axis);
            axis_combo(ui, "y-axis", "Y axis", &mut self.y_axis);
            egui::ComboBox::from_id_salt("group-by")
                .selected_text(self.group_by.label())
                .show_ui(ui, |ui| {
                    for group in GroupBy::ALL {
                        ui.selectable_value(&mut self.group_by, group, group.label());
                    }
                });
            ui.label("Drag to pan · wheel to zoom · double-click to reset");
        });

        let samples = self.analyzer.completed_ios();
        let origin_ns = samples.first().map_or(0, |io| io.completion.ts_ns);
        let mut groups: BTreeMap<String, Vec<[f64; 2]>> = BTreeMap::new();
        for io in samples.iter().rev().take(50_000).rev() {
            let (Some(x), Some(y)) = (
                self.x_axis.value(io, origin_ns),
                self.y_axis.value(io, origin_ns),
            ) else {
                continue;
            };
            groups
                .entry(self.group_by.key(io))
                .or_default()
                .push([x, y]);
        }
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
            .height(440.0)
            .x_axis_label(self.x_axis.label())
            .y_axis_label(self.y_axis.label())
            .legend(Legend::default())
            .show(ui, |plot| {
                for (index, (name, values)) in groups.into_iter().enumerate() {
                    let points: PlotPoints = values.into_iter().collect();
                    plot.points(
                        Points::new(name, points)
                            .radius(2.5)
                            .color(palette[index % palette.len()]),
                    );
                }
            });
        ui.small("Queue latency는 block_rq_insert가 지원되는 장비에서만 표시됩니다. 값이 없는 요청은 해당 series에서 제외됩니다.");
    }

    fn summary_ui(&self, ui: &mut egui::Ui) {
        let summary = self.analyzer.summary();
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
        ui.separator();
        ui.heading("Category summary");
        egui::ScrollArea::vertical()
            .max_height(420.0)
            .show(ui, |ui| {
                egui::Grid::new("category-summary")
                    .striped(true)
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
    }

    fn files_ui(&self, ui: &mut egui::Ui) {
        ui.label("파일 경로는 syscall 시점의 /proc/<pid>/fd/<fd>를 해석한 attribution이며, buffered writeback block request와의 exact correlation은 아닙니다.");
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("file-ios").striped(true).show(ui, |ui| {
                for heading in [
                    "End ns",
                    "Op",
                    "Requested",
                    "Completed",
                    "Latency",
                    "PID",
                    "FD",
                    "Confidence",
                    "Path",
                ] {
                    ui.strong(heading);
                }
                ui.end_row();
                for file in self.analyzer.file_ios().iter().rev().take(1_000) {
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
                    ui.label(file.path.as_deref().unwrap_or("<unresolved>"));
                    ui.end_row();
                }
            });
        });
    }

    fn table_ui(&self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical()
            .max_height(260.0)
            .stick_to_bottom(true)
            .show(ui, |ui| {
                egui::Grid::new("recent-ios").striped(true).show(ui, |ui| {
                    for heading in [
                        "Time ns", "Op", "Access", "Size", "Bytes", "Sector", "Queue", "Device",
                        "Total", "PID", "Comm",
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
                        ui.label(io.issue.pid.to_string());
                        ui.label(&io.issue.comm);
                        ui.end_row();
                    }
                });
            });
    }
}

impl eframe::App for StudioApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.drain_messages();
        ui.ctx()
            .request_repaint_after(std::time::Duration::from_millis(100));
        ui.horizontal_wrapped(|ui| {
            if ui.button("Refresh devices").clicked() {
                self.refresh();
            }
            egui::ComboBox::from_id_salt("device")
                .selected_text(self.selected_serial.as_deref().unwrap_or("Select device"))
                .show_ui(ui, |ui| {
                    for device in &self.devices {
                        ui.selectable_value(
                            &mut self.selected_serial,
                            Some(device.serial.clone()),
                            format!(
                                "{} · {} · {:?}",
                                device.serial,
                                device.model.as_deref().unwrap_or("unknown"),
                                device.state
                            ),
                        );
                    }
                });
            if ui.button("Preflight").clicked() {
                self.preflight();
            }
            if ui.button("Deploy + Start eBPF").clicked() {
                self.start_device();
            }
            if ui.button("Simulator").clicked() {
                self.start_simulator();
            }
            if ui.button("Stop").clicked() {
                self.stop();
            }
            if ui.button("Open session").clicked() {
                self.open_session();
            }
            if ui.button("Export CSV").clicked() {
                self.export_csv();
            }
        });
        ui.separator();
        ui.heading("Android eBPF Storage Studio");
        ui.label(RichText::new(&self.status).color(Color32::LIGHT_BLUE));
        self.metrics_ui(ui);
        ui.separator();
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.page, Page::Summary, "Summary");
            ui.selectable_value(&mut self.page, Page::Explorer, "Explorer");
            ui.selectable_value(&mut self.page, Page::Events, "Block events");
            ui.selectable_value(&mut self.page, Page::Files, "File I/O");
        });
        ui.separator();
        match self.page {
            Page::Summary => self.summary_ui(ui),
            Page::Explorer => self.explorer_ui(ui),
            Page::Events => {
                ui.heading("Recent completed block I/O");
                self.table_ui(ui);
            }
            Page::Files => self.files_ui(ui),
        }
        if let Some(report) = &self.preflight {
            ui.collapsing("Device capabilities", |ui| {
                ui.monospace(format!(
                    "root={} abi={} android={} kernel={} BTF={} tracefs={} insert={} issue={} complete={} file_syscalls={}",
                    report.root,
                    report.abi,
                    report.android_version,
                    report.kernel_release,
                    report.btf,
                    report.tracefs,
                    report.block_insert,
                    report.block_issue,
                    report.block_complete,
                    report.raw_syscalls
                ));
                ui.label(format!("UFS event paths: {}", report.ufs_events.len()));
            });
        }
        ui.collapsing("Diagnostics", |ui| {
            for value in &self.diagnostics {
                ui.monospace(value);
            }
        });
    }
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

fn axis_combo(ui: &mut egui::Ui, id: &str, label: &str, value: &mut AxisMetric) {
    ui.label(label);
    egui::ComboBox::from_id_salt(id)
        .selected_text(value.label())
        .show_ui(ui, |ui| {
            for metric in AxisMetric::ALL {
                ui.selectable_value(value, metric, metric.label());
            }
        });
}

fn summary_card(ui: &mut egui::Ui, label: &str, value: String) {
    ui.label(label);
    ui.heading(value);
}
