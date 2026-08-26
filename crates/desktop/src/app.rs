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
use eframe::egui::{self, Color32, RichText, Stroke};
use egui_plot::{Legend, Plot, PlotPoints, Points};

use crate::{
    adb::{AdbClient, AdbDevice, DeviceState, PreflightReport},
    capture::{self, CaptureHandle, HostMessage},
    session::{self, SessionWriter},
    simulator,
};

const MAX_RECENT: usize = 2_000;
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
    Summary,
    Explorer,
    Events,
    Files,
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
        ui.columns(3, |columns| {
            metric_card(
                &mut columns[0],
                "COMPLETED I/O",
                summary.completed_ios.to_string(),
                "requests",
                ACCENT,
            );
            metric_card(
                &mut columns[1],
                "READ / WRITE",
                format!(
                    "{} / {}",
                    format_bytes(summary.read_bytes),
                    format_bytes(summary.write_bytes)
                ),
                "transferred",
                GREEN,
            );
            metric_card(
                &mut columns[2],
                "P95 LATENCY",
                format_latency(summary.p95_latency_ns),
                "end-to-end",
                AMBER,
            );
        });
        ui.add_space(8.0);
        ui.columns(3, |columns| {
            metric_card(
                &mut columns[0],
                "P50 LATENCY",
                format_latency(summary.p50_latency_ns),
                "median",
                GREEN,
            );
            metric_card(
                &mut columns[1],
                "P99 LATENCY",
                format_latency(summary.p99_latency_ns),
                "tail",
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

    fn explorer_ui(&mut self, ui: &mut egui::Ui) {
        section_header(
            ui,
            "Interactive explorer",
            "Choose any dimensions, then pan and zoom directly on the plot.",
        );
        card_frame().show(ui, |ui| {
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
                ui.add_space(12.0);
                ui.label(
                    RichText::new("Drag: pan  •  Wheel: zoom  •  Double-click: reset").color(MUTED),
                );
            });
        });
        ui.add_space(10.0);

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
            .height(ui.available_height().max(420.0) - 42.0)
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
        ui.label(RichText::new("ⓘ Queue latency requires block_rq_insert. Missing values are excluded instead of displayed as zero.").small().color(MUTED));
    }

    fn summary_ui(&self, ui: &mut egui::Ui) {
        let summary = self.analyzer.summary();
        section_header(
            ui,
            "Session overview",
            "A concise view of utilization, attribution, and latency by workload class.",
        );
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
            egui::ScrollArea::vertical().show(ui, |ui| {
                egui::Grid::new("file-ios")
                    .striped(true)
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
                                "Time ns", "Op", "Access", "Size", "Bytes", "Sector", "Queue",
                                "Device", "Total", "PID", "Comm",
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
        });
    }
}

impl eframe::App for StudioApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.drain_messages();
        ui.ctx()
            .request_repaint_after(std::time::Duration::from_millis(100));
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
                    Page::Summary,
                    "▦",
                    "Summary",
                    "KPIs and workload mix",
                );
                nav_item(
                    ui,
                    &mut self.page,
                    Page::Explorer,
                    "⌁",
                    "Explorer",
                    "Interactive axes and groups",
                );
                nav_item(
                    ui,
                    &mut self.page,
                    Page::Events,
                    "≡",
                    "Block events",
                    "Request-level pipeline",
                );
                nav_item(
                    ui,
                    &mut self.page,
                    Page::Files,
                    "▤",
                    "File I/O",
                    "Syscall path attribution",
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
                                ui.label(RichText::new(value).monospace().size(10.0).color(RED));
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
                    self.metrics_ui(ui);
                    ui.add_space(20.0);
                    match self.page {
                        Page::Summary => self.summary_ui(ui),
                        Page::Explorer => self.explorer_ui(ui),
                        Page::Events => self.table_ui(ui),
                        Page::Files => self.files_ui(ui),
                    }
                    if let Some(report) = &self.preflight {
                        ui.add_space(14.0);
                        capability_panel(ui, report);
                    }
                });
            });
    }
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
                "{}  •  Android {}  •  Kernel {}  •  {} UFS event path(s)",
                report.abi,
                report.android_version,
                report.kernel_release,
                report.ufs_events.len()
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

    #[test]
    fn workflow_starts_with_connect_and_advances_after_device_selection() {
        let mut app = StudioApp::default();
        assert_eq!(app.setup_step(), SetupStep::Connect);

        app.selected_serial = Some("device-01".into());
        assert_eq!(app.setup_step(), SetupStep::Verify);
    }
}
