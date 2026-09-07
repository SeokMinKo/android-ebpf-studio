type IssuerIdentity = (Option<u32>, Option<u32>, String);
fn identity_number(value: Option<u32>) -> String {
    value.map_or_else(|| "unavailable".into(), |v| v.to_string())
}
fn issuer_label(pid: Option<u32>, tid: Option<u32>, name: &str) -> String {
    format!(
        "{name} · PID {} / TID {}",
        identity_number(pid),
        identity_number(tid)
    )
}
type IoSelectionKey = (u64, u64, u32, u32);
#[derive(Debug, Default)]
struct SelectedTarget {
    keys: std::collections::HashSet<IoSelectionKey>,
    count: u64,
    read_bytes: u64,
    write_bytes: u64,
    max_latency_ns: Option<u64>,
    processes: std::collections::BTreeSet<IssuerIdentity>,
    files: std::collections::BTreeSet<String>,
}
impl SelectedTarget {
    fn observe(&mut self, io: &CompletedIo) {
        self.keys.insert(selection_key(io));
        self.count += 1;
        match io.issue.operation {
            IoOperation::Read => self.read_bytes += io.issue.bytes as u64,
            IoOperation::Write => self.write_bytes += io.issue.bytes as u64,
            _ => {}
        }
        self.max_latency_ns = self.max_latency_ns.max(io.total_latency_ns);
    }
}
impl SelectionSummary {
    fn observe_targets(&mut self, io: &CompletedIo, origins: &[FileOriginView]) {
        let process = (io.issuer_pid(), io.issuer_tid(), io.issue.comm.clone());
        let process_row = self.processes.entry(process.clone()).or_default();
        process_row.observe(io);
        let mut identities = std::collections::BTreeSet::new();
        for origin in origins {
            let path = origin
                .path
                .as_ref()
                .and_then(|p| p.path.as_deref())
                .filter(|p| !p.is_empty());
            identities.insert((
                path.unwrap_or("<path unresolved>").to_owned(),
                origin.file.fallback_label(),
                if path.is_none() {
                    "Unresolved · no matching path snapshot".into()
                } else {
                    edge_confidence_label(origin.confidence).into()
                },
            ));
        }
        if identities.is_empty() {
            identities.insert((
                "<path unresolved>".into(),
                format!(
                    "block device {}:{} · inode unavailable",
                    io.issue.device_major, io.issue.device_minor
                ),
                "Unresolved · no defensible file evidence".into(),
            ));
        }
        if identities.len() > 1 {
            self.multiple_candidates += 1;
        }
        for identity in identities {
            process_row
                .files
                .insert(format!("{} · {} [{}]", identity.0, identity.1, identity.2));
            let row = self.files.entry(identity).or_default();
            row.observe(io);
            row.processes.insert(process.clone());
        }
    }
}

fn selected_targets_ui(
    ui: &mut egui::Ui,
    summary: &SelectionSummary,
    tab: InspectorTab,
    allow_filter: bool,
) -> Option<AnalysisFilter> {
    let mut query = None;
    ui.label("Selection snapshot · observed block issuer, not necessarily the application that dirtied cached data.");
    if tab == InspectorTab::Files {
        egui::CollapsingHeader::new(format!("Files / candidates ({})", summary.files.len())).default_open(true).show(ui, |ui| {
        ui.label(format!("{} I/O have multiple candidates. Candidate bytes overlap and must not be summed as attributed file bytes.",summary.multiple_candidates));
        let page = target_page(ui,"files-page",summary.files.len());
        egui::ScrollArea::vertical().id_salt("selected-files").max_height(10000.0).show(ui, |ui| {
            for ((path,identity,confidence), row) in summary.files.iter().skip(page*20).take(20) {
                ui.push_id((path,identity,confidence), |ui| {
                    ui.strong(path);
                    ui.small(format!("{identity} · {confidence}"));
                    target_metrics(ui,row);
                    ui.small(format!("Block issuers ({} total): {}",row.processes.len(), row.processes.iter().take(5).map(|(pid,tid,comm)|issuer_label(*pid,*tid,comm)).collect::<Vec<_>>().join(", ")));
                    if allow_filter && !path.starts_with('<') && ui.small_button("Filter this file in selection").clicked() {
                        query=Some(AnalysisFilter { request_keys:Some(row.keys.clone()), ..Default::default() });
                    }
                    ui.separator();
                });
            }
        });
    });
    }
    if tab == InspectorTab::Processes {
        egui::CollapsingHeader::new(format!("Processes / threads ({})", summary.processes.len())).default_open(true).show(ui, |ui| {
        let page = target_page(ui,"processes-page",summary.processes.len());
        egui::ScrollArea::vertical().id_salt("selected-processes").max_height(10000.0).show(ui, |ui| {
            for ((pid,tid,comm),row) in summary.processes.iter().skip(page*20).take(20) {
                ui.push_id((pid,tid,comm), |ui| {
                    ui.strong(issuer_label(*pid,*tid,comm));
                    target_metrics(ui,row);
                    ui.collapsing(format!("File evidence ({})",row.files.len()), |ui| { for file in row.files.iter().take(5) { ui.small(file); } if row.files.len()>5 {ui.small("Filter this issuer to browse all files in its graph selection.");} });
                    if allow_filter && ui.small_button("Filter this issuer in selection").clicked() {
                        query=Some(AnalysisFilter { request_keys:Some(row.keys.clone()), ..Default::default() });
                    }
                    ui.separator();
                });
            }
        });
    });
    }
    query
}
fn target_page(ui: &mut egui::Ui, salt: &str, count: usize) -> usize {
    let id = ui.make_persistent_id(salt);
    let last = count.saturating_sub(1) / 20;
    let mut page = ui
        .ctx()
        .data_mut(|data| data.get_temp::<usize>(id).unwrap_or(0))
        .min(last);
    if last > 0 {
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(page > 0, egui::Button::new("Previous 20"))
                .clicked()
            {
                page -= 1;
            }
            ui.label(format!("{} / {}", page + 1, last + 1));
            if ui
                .add_enabled(page < last, egui::Button::new("Next 20"))
                .clicked()
            {
                page += 1;
            }
        });
    }
    ui.ctx().data_mut(|data| data.insert_temp(id, page));
    page
}
fn target_metrics(ui: &mut egui::Ui, row: &SelectedTarget) {
    ui.label(format!(
        "{} I/O · R {} / W {}",
        row.count,
        format_bytes(row.read_bytes),
        format_bytes(row.write_bytes)
    ));
    ui.small(format!(
        "Max total latency {}",
        format_latency(row.max_latency_ns)
    ));
}

fn selection_key(io: &CompletedIo) -> IoSelectionKey {
    (
        io.issue.request_id,
        io.issue.ts_ns,
        io.issue.device_major,
        io.issue.device_minor,
    )
}

#[derive(Clone, Copy)]
enum SelectionRequest {
    Point(IoSelectionKey),
    Rectangle { min: [f64; 2], max: [f64; 2] },
}

#[derive(Debug, Default)]
struct DirectionSummary {
    count: u64,
    bytes: u64,
    chunks: [u64; 5],
    latency: Vec<u64>,
}
impl DirectionSummary {
    fn observe(&mut self, io: &CompletedIo) {
        self.count += 1;
        self.bytes = self.bytes.saturating_add(io.issue.bytes as u64);
        let bucket = match io.issue.bytes {
            0..=4096 => 0,
            4097..=16384 => 1,
            16385..=65536 => 2,
            65537..=262144 => 3,
            _ => 4,
        };
        self.chunks[bucket] += 1;
        if let Some(latency) = io.total_latency_ns {
            self.latency.push(latency);
        }
    }
    fn percentile(&self, p: usize) -> Option<u64> {
        if self.latency.is_empty() {
            None
        } else {
            self.latency
                .get((self.latency.len() * p).div_ceil(100).saturating_sub(1))
                .copied()
        }
    }
}

#[derive(Debug, Default)]
struct SelectionSummary {
    files: BTreeMap<(String, String, String), SelectedTarget>,
    processes: BTreeMap<IssuerIdentity, SelectedTarget>,
    multiple_candidates: u64,
    keys: std::collections::HashSet<IoSelectionKey>,
    start_ns: Option<u64>,
    end_ns: Option<u64>,
    unplaced_time_count: u64,
    read: DirectionSummary,
    write: DirectionSummary,
    other_count: u64,
    other_bytes: u64,
    access: [u64; 3],
    bounds: Option<egui_plot::PlotBounds>,
    elapsed: Duration,
}
impl SelectionSummary {
    fn observe(&mut self, io: &CompletedIo, point: [f64; 2]) {
        self.keys.insert(selection_key(io));
        if let Some((start, end)) = io.start_timestamp().zip(io.completion_timestamp()) {
            self.start_ns = Some(self.start_ns.map_or(start, |v| v.min(start)));
            self.end_ns = Some(self.end_ns.map_or(end, |v| v.max(end)));
        } else {
            self.unplaced_time_count += 1;
        }
        match io.issue.operation {
            IoOperation::Read => self.read.observe(io),
            IoOperation::Write => self.write.observe(io),
            _ => {
                self.other_count += 1;
                self.other_bytes += io.issue.bytes as u64;
            }
        }
        self.access[match io.access_pattern {
            AccessPattern::Random => 0,
            AccessPattern::Sequential => 1,
            AccessPattern::Unknown => 2,
        }] += 1;
        let bounds = self
            .bounds
            .get_or_insert_with(|| egui_plot::PlotBounds::from_min_max(point, point));
        bounds.extend_with(&egui_plot::PlotPoint::new(point[0], point[1]));
    }
    fn duration_ns(&self) -> Option<u64> {
        if self.unplaced_time_count > 0 {
            return None;
        }
        self.start_ns
            .zip(self.end_ns)
            .map(|(start, end)| end.saturating_sub(start))
    }
    fn throughput(&self, bytes: u64) -> Option<f64> {
        self.duration_ns()
            .filter(|v| *v > 0)
            .map(|ns| bytes as f64 * 1e9 / ns as f64 / 1_048_576.0)
    }
}

#[derive(Default)]
struct SelectionState {
    requested_at: Option<Instant>,
    wall_ms: Option<f64>,
    inspector_tab: InspectorTab,
    enabled: bool,
    drag_start: Option<[f64; 2]>,
    summary: Option<SelectionSummary>,
    pending: Option<Receiver<SelectionSummary>>,
    cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    queued: Option<SelectionRequest>,
    discard_pending: bool,
    bounds_command: Option<egui_plot::PlotBounds>,
    auto_bounds: bool,
    axis_range: AxisRangeEditor,
    current_bounds: Option<egui_plot::PlotBounds>,
    zoom_history: Vec<egui_plot::PlotBounds>,
}

impl SelectionState {
    fn has_selection(&self) -> bool {
        self.summary.is_some() || self.pending.is_some() || self.queued.is_some() || self.drag_start.is_some()
    }

    fn clear_selection(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        self.summary = None;
        self.pending = None;
        self.queued = None;
        self.drag_start = None;
        self.discard_pending = true;
        self.requested_at = None;
        self.wall_ms = None;
    }
}

#[cfg(test)]
fn compute_selection(
    engine: &AnalysisEngine,
    request: SelectionRequest,
    x: AxisMetric,
    y: AxisMetric,
    origin: u64,
) -> SelectionSummary {
    compute_selection_cancellable(engine, request, x, y, origin, None)
}

fn compute_selection_cancellable(
    engine: &AnalysisEngine,
    request: SelectionRequest,
    x: AxisMetric,
    y: AxisMetric,
    origin: u64,
    cancel: Option<&std::sync::atomic::AtomicBool>,
) -> SelectionSummary {
    let started = Instant::now();
    let mut result = SelectionSummary::default();
    for io in engine.completed_ios() {
        if cancel.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed)) {
            break;
        }
        if let SelectionRequest::Point(key) = request
            && selection_key(io) != key
        {
            continue;
        }
        let graph = (x.needs_graph() || y.needs_graph()).then(|| engine.transaction_for(io));
        let (Some(px), Some(py)) = (
            x.value(io, origin, graph.as_ref()),
            y.value(io, origin, graph.as_ref()),
        ) else {
            continue;
        };
        if !px.is_finite() || !py.is_finite() {
            continue;
        }
        if let SelectionRequest::Rectangle { min, max } = request
            && (px < min[0] || px > max[0] || py < min[1] || py > max[1])
        {
            continue;
        }
        result.observe(io, [px, py]);
        let graph = graph.unwrap_or_else(|| engine.transaction_for(io));
        result.observe_targets(io, &block_file_origins(&graph));
    }
    result.read.latency.sort_unstable();
    result.write.latency.sort_unstable();
    result.elapsed = started.elapsed();
    result
}

impl StudioApp {
    fn begin_selection(&mut self, request: SelectionRequest) {
        // Snapshot the current filtered cohort so live updates cannot change a
        // selection while the analyst reads it. Background work never blocks UI.
        if self.selection.pending.is_some() {
            self.selection.queued = Some(request);
            self.selection.discard_pending = true;
            return;
        }
        self.selection.discard_pending = false;
        self.selection.requested_at = Some(Instant::now());
        let engine = self.analysis().select_completed(|_| true);
        let (tx, rx) = bounded(1);
        self.selection.pending = Some(rx);
        let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        self.selection.cancel = Some(cancel.clone());
        let (x, y, origin) = (self.x_axis, self.y_axis, self.time_origin());
        std::thread::spawn(move || {
            let _ = tx.send(compute_selection_cancellable(&engine, request, x, y, origin, Some(&cancel)));
        });
    }

    fn poll_selection(&mut self) {
        if let Some(rx) = &self.selection.pending
            && let Ok(summary) = rx.try_recv()
        {
            self.selection.summary = (!self.selection.discard_pending).then_some(summary);
            self.selection.wall_ms = self
                .selection
                .requested_at
                .map(|t| t.elapsed().as_secs_f64() * 1000.0);
            self.selection.pending = None;
            self.selection.cancel = None;
            if let Some(request) = self.selection.queued.take() {
                self.begin_selection(request);
            }
        }
    }

    fn selection_panel(&mut self, ui: &mut egui::Ui) {
        self.poll_selection();
        let mut target_query = None;
        let mut panel = egui::Panel::right("selection-summary")
            .default_size(340.0)
            .size_range(260.0..=440.0)
            .resizable(true);
        if ui.ctx().content_rect().width() < 1100.0 {
            panel = panel.exact_size(280.0);
        }
        panel.show(ui, |ui| {
            ui.heading("Selection summary");
            ui.horizontal_wrapped(|ui| {
                let zoom_response = ui.add_enabled(self.selection.summary.as_ref().is_some_and(|s|!s.keys.is_empty()),egui::Button::new("Zoom selection"));
                qa_region(&mut self.render_qa,"zoom",zoom_response.rect,ui.clip_rect());
                self.render_qa.zoom_button = Some(zoom_response.rect.center());
                if zoom_response.clicked() {
                    self.render_qa.zoom_actions += 1;
                    self.selection.remember_view();
                    if let Some(bounds) = self.selection.summary.as_ref().and_then(|s|s.bounds) {
                        let min=bounds.min(); let max=bounds.max();
                        let dx=(max[0]-min[0]).abs().max(min[0].abs()*0.001).max(0.001)*0.05;
                        let dy=(max[1]-min[1]).abs().max(min[1].abs()*0.001).max(0.001)*0.05;
                        self.selection.bounds_command = Some(egui_plot::PlotBounds::from_min_max([min[0]-dx,min[1]-dy],[max[0]+dx,max[1]+dy]));
                    }
                }
                let back_response = ui.add_enabled(!self.selection.zoom_history.is_empty(),egui::Button::new("Back"));
                qa_region(&mut self.render_qa,"back",back_response.rect,ui.clip_rect());
                self.render_qa.back_button = Some(back_response.rect.center());
                if back_response.clicked() { self.render_qa.back_actions += 1; self.selection.bounds_command = self.selection.zoom_history.pop(); }

            });
            ui.horizontal(|ui| {
                for (tab,label) in [(InspectorTab::Summary,"Summary"),(InspectorTab::Files,"Files"),(InspectorTab::Processes,"Processes")] {
                    let response=ui.selectable_value(&mut self.selection.inspector_tab,tab,label);
                    qa_region(&mut self.render_qa,label,response.rect,ui.clip_rect());
                    self.render_qa.inspector_buttons.insert(label.into(),response.rect.center());
                }
            });
            ui.separator();
            if self.selection.pending.is_some() { ui.spinner(); ui.label("Calculating selected data…"); }
            let mut scroll = egui::ScrollArea::vertical().id_salt(("selection-scroll",format!("{:?}",self.selection.inspector_tab)));
            if self.render_qa.output.is_some() && let Ok(offset)=std::env::var("ANDROID_EBPF_QA_PANEL_SCROLL") && let Ok(offset)=offset.parse::<f32>() {scroll=scroll.vertical_scroll_offset(offset);}
            let origin=self.time_origin();
            scroll.show(ui, |ui| {
                let Some(s) = &self.selection.summary else { ui.add_space(8.0); ui.strong("Select I/O to inspect"); ui.label("Click a point or drag an area on the graph."); ui.collapsing("How selection works", |ui| { ui.label("Use Select to inspect or Pan to move the view. Area selection includes all plottable requests in the current filters, even when the plot is sampled. Clear selection cancels the selection without changing filters or zoom."); }); return; };
                if self.selection.inspector_tab != InspectorTab::Summary {
                    target_query=selected_targets_ui(ui,s,self.selection.inspector_tab,true);
                    return;
                }
                ui.horizontal(|ui| {
                    ui.label(RichText::new(s.keys.len().to_string()).size(24.0).strong().color(ink()));
                    ui.label("selected I/O").on_hover_text("Data Count: completed block I/O requests in the selection");
                });
                ui.label(format!("End − Start: {}",format_latency(s.duration_ns())));
                if s.unplaced_time_count == 0 && let Some((start,end))=s.start_ns.zip(s.end_ns) {
                    ui.small(format!("{:.2}–{:.2} ms from session origin",(start as f64-origin as f64)/1e6,(end as f64-origin as f64)/1e6));
                }
                if s.unplaced_time_count > 0 {
                    ui.label(format!("{} selected I/O have an unsupported clock. Selection span and throughput are unavailable; volume and identities include all selected I/O.",s.unplaced_time_count));
                }
                ui.horizontal_wrapped(|ui| {
                    if ui.link(format!("{} file candidates",s.files.len())).clicked() {self.selection.inspector_tab=InspectorTab::Files;}
                    if ui.link(format!("{} process / thread entries",s.processes.len())).clicked() {self.selection.inspector_tab=InspectorTab::Processes;}
                });
                ui.add_space(6.0);ui.separator();
                ui.label(RichText::new("Volume & throughput").strong().color(ink()));
                summary_metric_row(ui,"", "Read".into(), "Write".into(),true);
                summary_metric_row(ui,"I/O count",s.read.count.to_string(),s.write.count.to_string(),false);
                summary_metric_row(ui,"Size",format_bytes(s.read.bytes),format_bytes(s.write.bytes),false);
                summary_metric_row(ui,"MiB/s",s.throughput(s.read.bytes).map_or("—".into(),|v|format!("{v:.3}")),s.throughput(s.write.bytes).map_or("—".into(),|v|format!("{v:.3}")),false);
                ui.add_space(6.0);ui.separator();
                ui.label(RichText::new("Total latency").strong().color(ink()));
                ui.small("Insert (or issue) to completion · valid timing samples only");
                summary_metric_row(ui,"Timed / total",format!("{} / {}",s.read.latency.len(),s.read.count),format!("{} / {}",s.write.latency.len(),s.write.count),false);
                summary_metric_row(ui,"", "Read".into(), "Write".into(),true);
                for p in [50,90,95,99,100] {
                    summary_metric_row(ui,&if p==100 {"Max".into()} else {format!("P{p}")},format_latency(s.read.percentile(p)),format_latency(s.write.percentile(p)),false);
                }
                if s.other_count>0 {ui.small(format!("Other: {} requests · {}",s.other_count,format_bytes(s.other_bytes)));}
                ui.collapsing("Definitions & timestamps",|ui| {
                    ui.label(format!("Known-clock subset start: {} ns",s.start_ns.map_or("—".into(),|v|v.to_string())));
                    ui.label(format!("Known-clock subset end: {} ns",s.end_ns.map_or("—".into(),|v|v.to_string())));
                    ui.label("Span: earliest known insert/issue (completion when start is unknown) to latest completion. Throughput uses this observed span; it may omit unknown pre-completion time. — means unavailable. Percentiles use exact nearest rank over valid timing samples.");
                    ui.label(format!("Selection aggregation: {:.1} ms",s.elapsed.as_secs_f64()*1000.0));
                });
                ui.separator();
                ui.strong("Random / Sequential");
                ui.small("Request count · original block issue order");
                selection_pie(ui,&s.access,&["Random","Sequential","Unknown"]);
                ui.small("Per device and direction. Unknown stays visible.");
                for (label,side) in [("Read",&s.read),("Write",&s.write)] {
                    ui.separator();ui.strong(format!("{label} chunk size"));ui.small("Request count");
                    selection_pie(ui,&side.chunks,&["≤4 KiB","4–16 KiB","16–64 KiB","64–256 KiB",">256 KiB"]);
                }
                if s.elapsed>=Duration::from_secs(5) {ui.colored_label(red(),"Exceeded 5 s target; use a narrower cohort.");}
                if let Some(key) = s.keys.iter().next() && s.keys.len()==1 && ui.button("Investigate this I/O").clicked() {self.selected_pipeline_request=Some(*key);self.page=Page::Investigate;}
            });
        });
        if let Some(query) = target_query {
            self.query = query;
            self.invalidate_query();
            self.rebuild_filtered();
        }
    }
}

fn summary_metric_row(ui: &mut egui::Ui, label: &str, read: String, write: String, header: bool) {
    ui.columns(3, |cols| {
        cols[0].label(label);
        for (column, value) in cols[1..].iter_mut().zip([read, write]) {
            column.with_layout(egui::Layout::top_down(egui::Align::RIGHT), |ui| {
                let text = RichText::new(value).color(ink());
                ui.label(if header {
                    text.strong()
                } else {
                    text.monospace()
                });
            });
        }
    });
}

fn selection_pie(ui: &mut egui::Ui, values: &[u64], labels: &[&str]) {
    let total: u64 = values.iter().sum();
    if total == 0 {
        ui.label("No selected requests");
        return;
    }
    let colors = [accent(), green(), amber(), red(), muted()];
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(egui::vec2(90.0, 90.0), egui::Sense::hover());
        let center = rect.center();
        let radius = 40.0;
        let mut start = -std::f32::consts::FRAC_PI_2;
        for (i, value) in values.iter().enumerate() {
            let sweep = *value as f32 / total as f32 * std::f32::consts::TAU;
            let count = (sweep * 20.0).ceil().max(1.0) as usize;
            let mut mesh = egui::Mesh::default();
            mesh.colored_vertex(center, colors[i % colors.len()]);
            for step in 0..=count {
                let angle = start + sweep * step as f32 / count as f32;
                mesh.colored_vertex(
                    center + egui::vec2(angle.cos(), angle.sin()) * radius,
                    colors[i % colors.len()],
                );
                if step > 0 {
                    mesh.add_triangle(0, step as u32, step as u32 + 1);
                }
            }
            ui.painter().add(egui::Shape::mesh(mesh));
            start += sweep;
        }
        ui.vertical(|ui| {
            for (i, (value, label)) in values.iter().zip(labels).enumerate() {
                ui.colored_label(
                    colors[i % colors.len()],
                    format!("{label}: {value} ({:.1}%)", ratio(*value, total)),
                );
            }
        });
    });
}

#[cfg(test)]
mod selection_tests {
    use super::*;
    use android_ebpf_protocol::{BlockComplete, BlockIssue, StorageEvent};

    fn fixture(count: u64) -> AnalysisEngine {
        let mut engine = AnalysisEngine::new();
        for id in 1..=count {
            engine.ingest(StorageEvent::BlockIssue(BlockIssue {
                ts_ns: id * 1_000_000,
                request_id: id,
                device_major: 8,
                device_minor: 0,
                sector: id * 8,
                sectors: 8,
                bytes: 4096,
                operation: if id.is_multiple_of(2) {
                    IoOperation::Write
                } else {
                    IoOperation::Read
                },
                pid: 1,
                tid: 2,
                cpu: 0,
                comm: "selection-fixture".into(),
            }));
            engine.ingest(StorageEvent::BlockComplete(BlockComplete {
                ts_ns: id * 1_000_000 + 500_000,
                request_id: id,
                device_major: 8,
                device_minor: 0,
                status: 0,
            }));
        }
        engine
    }

    #[test]
    fn rectangle_counts_all_requests_and_uses_selected_time_span_for_throughput() {
        let engine = fixture(10);
        let summary = compute_selection(
            &engine,
            SelectionRequest::Rectangle {
                min: [0.0, 0.0],
                max: [100.0, 1000.0],
            },
            AxisMetric::TimeMs,
            AxisMetric::Sector,
            0,
        );
        assert_eq!(summary.keys.len(), 10);
        assert_eq!(summary.read.count, 5);
        assert_eq!(summary.write.bytes, 20480);
        assert_eq!(summary.duration_ns(), Some(9_500_000));
        assert_eq!(summary.read.percentile(99), Some(500_000));
        assert!((summary.throughput(20480).unwrap() - 2.0559210526).abs() < 0.00001);
        assert_eq!(summary.read.chunks, [5, 0, 0, 0, 0]);
        assert_eq!(summary.access.iter().sum::<u64>(), 10);
    }

    #[test]
    fn a_point_is_one_request_and_empty_selection_has_no_invented_latency() {
        let engine = fixture(10);
        let summary = compute_selection(
            &engine,
            SelectionRequest::Point((4, 4_000_000, 8, 0)),
            AxisMetric::TimeMs,
            AxisMetric::Sector,
            0,
        );
        assert_eq!(summary.keys.len(), 1);
        assert_eq!(summary.write.count, 1);
        assert_eq!(summary.duration_ns(), Some(500_000));
        assert_eq!(summary.read.percentile(50), None);
        let empty = compute_selection(
            &engine,
            SelectionRequest::Point((4, 4_000_000, 8, 1)),
            AxisMetric::TimeMs,
            AxisMetric::Sector,
            0,
        );
        assert_eq!(empty.keys.len(), 0);
        assert_eq!(empty.throughput(0), None);
    }

    #[test]
    fn selected_files_preserve_multiple_candidates_and_issuer_relationships() {
        let engine = fixture(2);
        let io = &engine.completed_ios()[0];
        let file = FileOriginView {
            incomplete: false,
            file: android_ebpf_protocol::FileIdentity {
                fs_device_major: 254,
                fs_device_minor: 1,
                inode: 42,
                inode_generation: None,
                mount_id: None,
            },
            path: Some(android_ebpf_protocol::PathSnapshot {
                path: Some("/data/a".into()),
                source: android_ebpf_protocol::PathSource::ProcFd,
                captured_ts_ns: 1,
                deleted: false,
            }),
            confidence: EdgeConfidence::Probable,
        };
        let mut second = file.clone();
        second.file.inode = 43;
        second.path = None;
        let mut summary = SelectionSummary::default();
        summary.observe_targets(io, &[file.clone(), file, second]);
        assert_eq!(summary.multiple_candidates, 1);
        assert_eq!(
            summary.files.len(),
            2,
            "duplicate evidence is not another file"
        );
        assert_eq!(summary.processes.len(), 1);
        assert_eq!(summary.processes.values().next().unwrap().read_bytes, 4096);
        assert!(
            summary
                .files
                .values()
                .all(|v| v.count == 1 && v.keys.len() == 1 && v.processes.len() == 1)
        );
        assert!(
            summary
                .files
                .keys()
                .any(|v| v.0 == "<path unresolved>" && v.2.contains("Unresolved"))
        );
        let query = AnalysisFilter {
            request_keys: Some(summary.files.values().next().unwrap().keys.clone()),
            ..Default::default()
        };
        assert!(query.matches(&engine, io, 0));
        assert!(!query.matches(&engine, &engine.completed_ios()[1], 0));
    }

    #[test]
    fn selection_of_100000_requests_finishes_within_five_seconds() {
        let engine = fixture(100_000);
        let start = Instant::now();
        let snapshot = engine.select_completed(|_| true);
        let summary = compute_selection(
            &snapshot,
            SelectionRequest::Rectangle {
                min: [0.0, 0.0],
                max: [f64::MAX, f64::MAX],
            },
            AxisMetric::TimeMs,
            AxisMetric::Sector,
            0,
        );
        let elapsed = start.elapsed();
        eprintln!(
            "SELECTION_BENCHMARK requests={} snapshot_and_aggregation_ms={:.3} build={} os={}",
            summary.keys.len(),
            elapsed.as_secs_f64() * 1000.0,
            if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            },
            std::env::consts::OS
        );
        assert_eq!(summary.keys.len(), 100_000);
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
    }
}

#[cfg(test)]
mod clear_selection_regression {
    use super::*;
    #[test]
    fn clear_cancels_pending_work_and_preserves_view() {
        let (tx, rx) = bounded(1);
        let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let bounds = egui_plot::PlotBounds::from_min_max([1.0, 2.0], [3.0, 4.0]);
        let mut state = SelectionState {
            summary: Some(SelectionSummary::default()),
            pending: Some(rx), cancel: Some(cancel.clone()),
            queued: Some(SelectionRequest::Point((1, 2, 8, 0))),
            drag_start: Some([2.0, 3.0]),
            current_bounds: Some(bounds), bounds_command: Some(bounds), zoom_history: vec![bounds],
            ..Default::default()
        };
        state.clear_selection();
        assert!(!state.has_selection());
        assert!(cancel.load(std::sync::atomic::Ordering::Relaxed));
        assert!(tx.try_send(SelectionSummary::default()).is_err(), "late worker must not restore selection");
        assert_eq!(state.current_bounds, Some(bounds));
        assert_eq!(state.bounds_command, Some(bounds));
        assert_eq!(state.zoom_history, vec![bounds]);
    }
    #[test]
    fn canceled_worker_stops_before_attribution() {
        let mut engine = AnalysisEngine::new();
        for line in include_str!("../tests/fixtures/known-read-tooltip.ndjson").lines() {
            if let WireRecord::Event {event, ..} = serde_json::from_str(line).unwrap() { engine.ingest(event); }
        }
        let cancel = std::sync::atomic::AtomicBool::new(true);
        let summary = compute_selection_cancellable(&engine, SelectionRequest::Rectangle {min: [0.0, 0.0], max: [f64::MAX, f64::MAX]}, AxisMetric::TimeMs, AxisMetric::AddressMB, 0, Some(&cancel));
        assert!(summary.keys.is_empty());
        assert!(summary.files.is_empty());
    }
}
