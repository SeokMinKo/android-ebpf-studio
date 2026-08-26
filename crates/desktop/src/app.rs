use std::{
    collections::VecDeque,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use android_ebpf_protocol::{AnalysisEngine, CompletedIo, SCHEMA_VERSION, WireRecord};
use crossbeam_channel::{Receiver, Sender, bounded};
use eframe::egui::{self, Color32, RichText};
use egui_plot::{Legend, Line, Plot, PlotPoints};

use crate::{
    adb::{AdbClient, AdbDevice, DeviceState, PreflightReport},
    capture::{self, CaptureHandle, HostMessage},
    session::{self, SessionWriter},
    simulator,
};

const MAX_RECENT: usize = 2_000;

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

    fn plot_ui(&self, ui: &mut egui::Ui) {
        let buckets = self.analyzer.buckets();
        let iops: PlotPoints = buckets
            .iter()
            .map(|bucket| [bucket.second as f64, bucket.completed_ios as f64])
            .collect();
        let bandwidth: PlotPoints = buckets
            .iter()
            .map(|bucket| [bucket.second as f64, bucket.bytes as f64 / 1_048_576.0])
            .collect();
        Plot::new("storage-rate")
            .height(260.0)
            .legend(Legend::default())
            .show(ui, |plot| {
                plot.line(Line::new("IOPS", iops).color(Color32::LIGHT_BLUE));
                plot.line(Line::new("MiB/s", bandwidth).color(Color32::LIGHT_GREEN));
            });
    }

    fn table_ui(&self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical()
            .max_height(260.0)
            .stick_to_bottom(true)
            .show(ui, |ui| {
                egui::Grid::new("recent-ios").striped(true).show(ui, |ui| {
                    for heading in ["Time ns", "Op", "Bytes", "Sector", "Latency", "PID", "Comm"] {
                        ui.strong(heading);
                    }
                    ui.end_row();
                    for io in self.recent.iter().rev().take(200) {
                        ui.label(io.completion.ts_ns.to_string());
                        ui.label(format!("{:?}", io.issue.operation));
                        ui.label(io.issue.bytes.to_string());
                        ui.label(io.issue.sector.to_string());
                        ui.label(format_latency(Some(io.latency_ns)));
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
        self.plot_ui(ui);
        ui.heading("Recent completed block I/O");
        self.table_ui(ui);
        if let Some(report) = &self.preflight {
            ui.collapsing("Device capabilities", |ui| {
                ui.monospace(format!(
                    "root={} abi={} android={} kernel={} BTF={} tracefs={} block_issue={} block_complete={}",
                    report.root,
                    report.abi,
                    report.android_version,
                    report.kernel_release,
                    report.btf,
                    report.tracefs,
                    report.block_issue,
                    report.block_complete
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
