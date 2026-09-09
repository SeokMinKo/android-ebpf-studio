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
    companion_distributions:BTreeMap<String,crate::graph_summary::MetricDistribution>,
    timeline:Option<TimelineView>,
    window_series:Option<crate::window_series::WindowSeries>,
    categories:BTreeMap<String,BTreeMap<String,(u64,u64)>>,
    host_bw:Option<crate::host_bw::HostBandwidth>,
    source_rows: usize,
    unplottable_rows: usize,
    metric_axis: Option<AxisMetric>,
    metric: crate::graph_summary::MetricDistribution,
    address_distributions: BTreeMap<(u32,u32), crate::graph_summary::MetricDistribution>,
    address_counts: Vec<crate::graph_summary::AddressCount>,
    locality:BTreeMap<(u32,u32),crate::graph_summary::AddressLocality>,
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
        for (dimension,label) in [
            ("Command",format!("{:?}",io.issue.operation)),
            ("Access pattern",format!("{:?}",io.access_pattern)),
            ("Size class",format!("{:?}",io.size_class)),
            ("Chunk size",format!("{} B",io.issue.bytes)),
            ("Command / access / size",format!("{:?} / {:?} / {:?}",io.issue.operation,io.access_pattern,io.size_class)),
            ("Device",format!("{}:{}",io.issue.device_major,io.issue.device_minor)),
            ("Issue CPU",identity_number(io.issuer_cpu())),
            ("Completion CPU",identity_number(io.completion.cpu)),
            ("Process",format!("{}:{} / {} · PID {}",io.issue.device_major,io.issue.device_minor,io.issue.comm,identity_number(io.issuer_pid()))),
        ] {self.observe_category(dimension,label,io);}
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
    fn observe_category(&mut self,dimension:&str,label:String,io:&CompletedIo) {
        let row=self.categories.entry(dimension.into()).or_default().entry(label).or_default();
        row.0+=1;
        if matches!(io.issue.operation,IoOperation::Read|IoOperation::Write) {row.1+=io.issue.bytes as u64;}
    }
}

struct SummaryWork {
    receiver: Receiver<SelectionSummary>,
    cancelled: Arc<AtomicBool>,
}
impl Drop for SummaryWork {
    fn drop(&mut self) {self.cancelled.store(true,Ordering::Relaxed);}
}
impl SummaryWork {
    fn try_recv(&self)->Result<SelectionSummary,crossbeam_channel::TryRecvError> {self.receiver.try_recv()}
}

#[derive(Default)]
struct SelectionState {
    all_refresh: Option<Instant>,
    all_summary: Option<(u64, AxisMetric, AxisMetric, SelectionSummary)>,
    all_pending: Option<(u64, AxisMetric, AxisMetric, SummaryWork)>,
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

fn compute_selection(
    engine: &AnalysisEngine,
    request: SelectionRequest,
    x: AxisMetric,
    y: AxisMetric,
    origin: u64,
) -> SelectionSummary {
    compute_selection_cancellable(engine,request,x,y,origin,None).expect("uncancelled selection")
}
fn compute_selection_cancellable(engine:&AnalysisEngine,request:SelectionRequest,x:AxisMetric,y:AxisMetric,origin:u64,cancelled:Option<&AtomicBool>)->Option<SelectionSummary> {
    if cancelled.is_some_and(|c|c.load(Ordering::Relaxed)) {return None;}
    let started = Instant::now();
    let metric_axis = if y == AxisMetric::TimeMs { x } else { y };
    let mut result = SelectionSummary {
        source_rows: engine.completed_ios().len(),
        metric_axis: Some(metric_axis),
        ..Default::default()
    };
    let x_categories=AxisCategories::build(engine,x);let y_categories=AxisCategories::build(engine,y);
    let mut addresses = crate::graph_summary::AddressAccumulator::default();
    let mut locality = crate::graph_summary::LocalityAccumulator::default();
    for io in engine.completed_ios() {
        if cancelled.is_some_and(|c|c.load(Ordering::Relaxed)) {return None;}
        if let SelectionRequest::Point(key) = request
            && selection_key(io) != key
        {
            continue;
        }
        let graph = (x.needs_graph() || y.needs_graph()).then(|| engine.transaction_for(io));
        let (Some(px), Some(py)) = (
            x_categories.value(x,io, origin, graph.as_ref()),
            y_categories.value(y,io, origin, graph.as_ref()),
        ) else {
            result.unplottable_rows += 1;
            continue;
        };
        if !px.is_finite() || !py.is_finite() {
            result.unplottable_rows += 1;
            continue;
        }
        if let SelectionRequest::Rectangle { min, max } = request
            && (px < min[0] || px > max[0] || py < min[1] || py > max[1])
        {
            continue;
        }
        result.observe(io, [px, py]);
        let mut companion_axes=vec![AxisMetric::ChunkKiB,AxisMetric::IssueQueueDepth];
        for axis in [x,y] {if axis!=AxisMetric::TimeMs && !matches!(axis,AxisMetric::Category(_)) && !companion_axes.contains(&axis) {companion_axes.push(axis);}}
        for axis in companion_axes {result.companion_distributions.entry(axis.label().into()).or_default().observe(io.issue.operation,axis.value(io,origin,graph.as_ref()));}
        for (i,axis) in [x,y].into_iter().enumerate() {if let AxisMetric::Category(c)=axis && (i==0 || x!=y) {result.observe_category(&format!("Axis: {}",c.label()),c.key(io,graph.as_ref()),io);}}
        if !matches!(metric_axis,AxisMetric::Category(_)) {result.metric.observe(io.issue.operation, metric_axis.value(io, origin, graph.as_ref()));}
        if matches!(metric_axis, AxisMetric::Sector | AxisMetric::AddressKiB | AxisMetric::AddressMB) {
            result.address_distributions.entry((io.issue.device_major, io.issue.device_minor)).or_default()
                .observe(io.issue.operation, metric_axis.value(io, origin, graph.as_ref()));
            addresses.observe(io);
            locality.observe(io);
        }
        let graph = graph.unwrap_or_else(|| engine.transaction_for(io));
        result.observe_targets(io, &block_file_origins(&graph));
        let layers:std::collections::BTreeSet<_>=graph.nodes.iter().map(|n|format!("{:?}",n.kind)).collect();
        for layer in layers {result.observe_category("Observed layer membership",layer,io);}
    }
    if cancelled.is_some_and(|c|c.load(Ordering::Relaxed)) {return None;}
    result.read.latency.sort_unstable();
    result.write.latency.sort_unstable();
    result.metric.finish();
    for d in result.companion_distributions.values_mut() {d.finish();}
    for dist in result.address_distributions.values_mut() { dist.finish(); }
    result.address_counts = addresses.finish();
    result.locality=locality.finish();
    result.categories.insert("File candidate membership".into(),result.files.iter().map(|((path,identity,confidence),r)|(format!("{path} / {identity} [{confidence}]"),(r.count,r.read_bytes.saturating_add(r.write_bytes)))).collect());
    result.elapsed = started.elapsed();
    Some(result)
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
        let bw=self.bandwidth_context(if matches!(self.y_axis,AxisMetric::Window(_)){None}else{Some(request)});
        let width=self.window_width_ms;
        let (tx, rx) = bounded(1);
        self.selection.pending = Some(rx);
        let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        self.selection.cancel = Some(cancel.clone());
        let (x, y, origin) = (self.x_axis, self.y_axis, self.time_origin());
        std::thread::spawn(move || {
            if let Some(summary) = compute_graph_selection_cancellable(&engine, request, [x, y], origin, bw, width, Some(&cancel)) { let _ = tx.send(summary); }
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
        if self.y_axis == AxisMetric::SchedulerIoWait {
            // This population has no request-summary consumer. Detach old work
            // when changing views so neither stale statistics nor pending state survives.
            self.selection.all_pending=None;self.selection.all_summary=None;
            self.selection.pending=None;self.selection.summary=None;self.selection.queued=None;
            self.scheduler_panel(ui); return;
        }
        self.poll_selection();
        self.poll_graph_summary();
        let live=self.is_running();
        let mut target_query = None;
        let mut export_keys = None;
        let mut panel = egui::Panel::right("selection-summary")
            .default_size(340.0)
            .size_range(260.0..=440.0)
            .resizable(true);
        if ui.ctx().content_rect().width() < 1100.0 {
            panel = panel.exact_size(280.0);
        }
        panel.show(ui, |ui| {
            ui.heading("Graph summary");
            ui.horizontal_wrapped(|ui| {
                let zoom_response = ui.add_enabled(self.selection.summary.as_ref().is_some_and(|s|s.bounds.is_some()),egui::Button::new("Zoom selection"));
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
                let selected = self.selection.summary.is_some();
                let Some(s) = self.selection.summary.as_ref().or_else(|| self.selection.all_summary.as_ref().map(|v| &v.3)) else { ui.spinner(); ui.label("Calculating current graph summary…"); return; };
                ui.small(if selected { "Selected graph region · Clear selection restores full filtered graph" } else { "Full filtered graph · select an area to narrow the summary" });
                if let Some(series)=&s.window_series {ui.small(format!("{} filtered source I/O · {} {}",s.source_rows,series.samples.len(),series.metric.population()));}
                else {ui.small(format!("{} filtered source I/O · {} cannot be plotted on these axes",s.source_rows,s.unplottable_rows));}
                if live && !selected {ui.small("Live snapshot · refreshed in background; incoming I/O may be newer");}
                if selected && ui.button("Apply selection to analysis filters").clicked() {
                    let mut query=self.query.clone();
                    query.request_keys=Some(s.keys.clone());
                    if let Some(b)=&s.host_bw {
                        query.start_ms=b.start_ns.saturating_sub(origin) as f64/1e6;
                        query.end_ms=b.end_ns.saturating_sub(origin) as f64/1e6;
                    }
                    target_query=Some(query);
                }
                if self.selection.inspector_tab != InspectorTab::Summary {
                    target_query=selected_targets_ui(ui,s,self.selection.inspector_tab,true);
                    return;
                }
                ui.horizontal(|ui| {
                    ui.label(RichText::new(s.keys.len().to_string()).size(24.0).strong().color(ink()));
                    ui.label(if selected {"selected I/O"} else if s.window_series.is_some() {"contributing I/O"}else{"plottable I/O"}).on_hover_text("Full-resolution completed requests in this graph cohort; display sampling never changes this count");
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
                graph_distribution_ui(ui, s);
                if ui.button("Export this graph's I/O CSV").clicked() {export_keys=Some(s.keys.clone());}
                ui.small("One row per graph-cohort request. Empty timing fields mean unavailable; file candidates share one row.");
                ui.separator();
                host_bw_ui(ui,s);
                if s.keys.is_empty() && s.unplottable_rows>0 {ui.small("Choose a measured axis or reanalyze available original events. Transfer and latency statistics for this graph cohort are unavailable.");return;}
                ui.separator();
                ui.label(RichText::new("Transfer volume").strong().color(ink()));
                summary_metric_row(ui,"", "Read".into(), "Write".into(),true);
                summary_metric_row(ui,"I/O count",s.read.count.to_string(),s.write.count.to_string(),false);
                summary_metric_row(ui,"Size",format_bytes(s.read.bytes),format_bytes(s.write.bytes),false);
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
                    ui.label("Span: earliest known insert/issue (completion when start is unknown) to latest completion. Host BW uses the explicit analysis interval and known-clock eligibility described above. — means unavailable. Percentiles use exact nearest rank over valid timing samples.");
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
        if let Some(keys)=export_keys {self.export_io_cohort_csv(Some(keys));}
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
    selection_pie_values(ui,values,labels,|value|value.to_string());
}
fn selection_pie_values(ui:&mut egui::Ui,values:&[u64],labels:&[&str],format_value:impl Fn(u64)->String) {
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
                    format!("{label}: {} ({:.1}%)", format_value(*value),ratio(*value, total)),
                );
            }
        });
    });
}

#[cfg(test)]
mod selection_tests {
    use super::*;
    use android_ebpf_protocol::{BlockComplete, BlockIssue, StorageEvent};

    #[test]
    fn lba_default_uses_phone_capacity_without_overriding_manual_zoom() {
        for gb in [128,256,512,1000] {
            let mut app=StudioApp {analyzer:fixture(100),..Default::default()};
            app.storage_range.detected_bytes=Some(gb*1_000_000_000);
            app.analyzer.ingest(StorageEvent::BlockIssue(BlockIssue {ts_ns:101_000_000,request_id:101,device_major:8,device_minor:0,sector:u64::MAX/2,sectors:8,bytes:4096,operation:IoOperation::Read,pid:1,tid:1,cpu:0,comm:"outlier".into()}));
            app.analyzer.ingest(StorageEvent::BlockComplete(BlockComplete {cpu:None,ts_ns:102_000_000,request_id:101,device_major:8,device_minor:0,status:0}));
            let ctx=egui::Context::default();
            let frame=|app:&mut StudioApp| {
                let mut output=ctx.run_ui(egui::RawInput {screen_rect:Some(egui::Rect::from_min_size(egui::Pos2::ZERO,egui::vec2(1600.,1000.))),..Default::default()},|root| {egui::CentralPanel::default().show(root,|ui| {app.explorer_plot_ui(ui,true);});});
                output.textures_delta.clear();
            };
            for _ in 0..3 {frame(&mut app);}
            let bounds=app.selection.current_bounds.unwrap();
            assert_eq!([bounds.min()[1],bounds.max()[1]],[0.,gb as f64*1000.]);
            assert_eq!(app.analysis().completed_ios().len(),101,"Outliers stay in the cohort");
            app.selection.bounds_command=Some(egui_plot::PlotBounds::from_min_max([0.,10.],[100.,20.]));
            for _ in 0..3 {frame(&mut app);}
            assert_eq!(app.selection.current_bounds.unwrap().max()[1],20.,"Manual zoom persists");
            app.selection.fit_axis_ranges();frame(&mut app);
            assert_eq!(app.selection.current_bounds.unwrap().max()[1],gb as f64*1000.);
        }
    }

    #[test]
    fn address_axis_labels_survive_maximized_viewports() {
        let mut failures=Vec::new();
        for size in [egui::vec2(1500.,940.), egui::vec2(1920.,1080.), egui::vec2(2880.,1660.), egui::vec2(3840.,2160.)] {
            for (lo,hi) in [(0.,500_000.),(45000.,47000.),(45615.,45616.),(45615.02,45615.07)] {
                let mut app = StudioApp {analyzer:fixture(100),..Default::default()};
                app.x_axis=AxisMetric::TimeMs; app.y_axis=AxisMetric::AddressMB;
                app.selection.bounds_command=Some(egui_plot::PlotBounds::from_min_max([7290.,lo],[7460.,hi]));
                let ctx=egui::Context::default();
                for n in 0..4 {
                    let mut output=ctx.run_ui(egui::RawInput {screen_rect:Some(egui::Rect::from_min_size(egui::Pos2::ZERO,size)),..Default::default()},|root| {
                        egui::CentralPanel::default().show(root,|ui| {app.explorer_plot_ui(ui,false);});
                    });
                    output.textures_delta.clear();
                    if n<3 {continue;}
                    let plot=app.render_qa.plot_rect.unwrap();
                    let labels:Vec<_>=output.shapes.iter().filter_map(|s| {
                        if let egui::Shape::Text(t)=&s.shape {
                            let rect=s.shape.visual_bounding_rect();
                            if t.galley.text().parse::<f64>().is_ok() && rect.center().x<plot.left() && rect.center().y>plot.top() && rect.center().y<plot.bottom() && rect.intersects(s.clip_rect) {
                                return Some(t.galley.text().to_string());
                            }
                        }
                        None
                    }).collect();
                    if labels.len()<2 {failures.push(format!("Y labels missing at {size:?}, {lo}..{hi}: {labels:?}"));}
                    let x_labels:Vec<_>=output.shapes.iter().filter_map(|s| {
                        if let egui::Shape::Text(t)=&s.shape {
                            let rect=s.shape.visual_bounding_rect();
                            if rect.center().y>plot.bottom() && rect.top()<plot.bottom()+35. && rect.center().x>plot.left() && rect.center().x<plot.right() && t.galley.text().parse::<f64>().is_ok() {return Some((t.galley.text().to_string(),rect));}
                        }
                        None
                    }).collect();
                    assert!(x_labels.len()>=4,"Need detailed time ticks at {size:?}: {x_labels:?}");
                    for (i,(_,a)) in x_labels.iter().enumerate() {for (_,b) in x_labels.iter().skip(i+1) {assert!(!a.intersects(*b),"Time labels overlap");}}
                }
            }
        }
        assert!(failures.is_empty(),"{}",failures.join("\n"));
    }

    #[test]
    fn explore_primary_drag_zooms_only_in_zoom_mode() {
        for selecting in [false, true] {
            for reverse in [false, true] {
                let mut app = StudioApp { analyzer: fixture(100), ..Default::default() };
                app.selection.enabled = selecting;
                app.x_axis = AxisMetric::TimeMs;
                app.y_axis = AxisMetric::Sector;
                let ctx = egui::Context::default();
                let mut time = 0.0;
                let mut frame = |app: &mut StudioApp, events| {
                    time += 0.1;
                    let mut output = ctx.run_ui(egui::RawInput {
                        time: Some(time),
                        screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1200.0, 800.0))),
                        events,
                        ..Default::default()
                    }, |root| {
                        egui::CentralPanel::default().show(root, |ui| { app.explorer_plot_ui(ui, true); });
                    });
                    output.textures_delta.clear();
                };
                for _ in 0..4 { frame(&mut app, vec![]); }
                let before = app.selection.current_bounds.unwrap();
                let rect = app.render_qa.plot_rect.unwrap();
                let a = rect.min + rect.size() * 0.3;
                let b = rect.min + rect.size() * 0.7;
                let (start, end) = if reverse { (b, a) } else { (a, b) };
                frame(&mut app, vec![egui::Event::PointerMoved(start), egui::Event::PointerButton {
                    pos: start, button: egui::PointerButton::Primary, pressed: true, modifiers: Default::default()
                }]);
                frame(&mut app, vec![egui::Event::PointerMoved(start + (end - start) * 0.1)]);
                frame(&mut app, vec![egui::Event::PointerMoved(end)]);
                frame(&mut app, vec![egui::Event::PointerButton {
                    pos: end, button: egui::PointerButton::Primary, pressed: false, modifiers: Default::default()
                }]);
                frame(&mut app, vec![]);
                let after = app.selection.current_bounds.unwrap();
                if selecting {
                    assert_eq!(before, after, "Select must not change the viewport");
                    assert!(app.selection.pending.is_some() || app.selection.summary.is_some());
                } else {
                    assert!(after.width() < before.width() * 0.6);
                    assert!(after.height() < before.height() * 0.6);
                    assert!(after.min()[0] > before.min()[0] && after.max()[0] < before.max()[0]);
                    assert!(!app.selection.has_selection(), "Zoom must not select I/O");
                }
            }
        }
    }

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
            engine.ingest(StorageEvent::BlockComplete(BlockComplete {cpu:None,
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
    fn exact_chunk_categories_preserve_bytes_zero_non_payload_and_unique_cohort() {
        let engine=fixture(1);
        let mut io=engine.completed_ios()[0].clone();
        let mut summary=SelectionSummary::default();
        for (index,(bytes,op)) in [(1000,IoOperation::Read),(1001,IoOperation::Read),(1000,IoOperation::Write),(0,IoOperation::Flush),(1_073_741_824,IoOperation::Discard)].into_iter().enumerate() {
            io.issue.bytes=bytes;io.issue.operation=op;io.issue.request_id=index as u64;
            summary.observe(&io,[index as f64,bytes as f64/1024.]);
        }
        let sizes=&summary.categories["Chunk size"];
        assert_eq!(sizes.len(),4);
        assert_eq!(sizes["1000 B"],(2,2000));assert_eq!(sizes["1001 B"],(1,1001));
        assert_eq!(sizes["0 B"],(1,0));assert_eq!(sizes["1073741824 B"],(1,0));
        assert_eq!(sizes.values().map(|v|v.0).sum::<u64>(),5);
        assert_eq!(sizes.values().map(|v|v.1).sum::<u64>(),3001);
        let path=std::env::temp_dir().join(format!("chunk-categories-{}.csv",uuid::Uuid::new_v4()));
        write_graph_summary_csv(&path,&summary).unwrap();
        let records=csv::Reader::from_path(&path).unwrap().records().collect::<Result<Vec<_>,_>>().unwrap();
        assert!(records.iter().any(|r|&r[0]=="category"&&&r[1]=="Chunk size"&&&r[2]=="1001 B"&&r[5]==*"1001"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn graph_summary_follows_chunk_latency_qd_and_lba_instead_of_fixed_latency() {
        let engine=fixture(10);
        let all=SelectionRequest::Rectangle{min:[f64::NEG_INFINITY;2],max:[f64::INFINITY;2]};
        for (axis,p50) in [(AxisMetric::ChunkKiB,4.),(AxisMetric::TotalLatencyMs,0.5),(AxisMetric::QueueDepth,0.),(AxisMetric::Sector,40.)] {
            let summary=compute_selection(&engine,all,AxisMetric::TimeMs,axis,0);
            assert_eq!(summary.metric_axis,Some(axis));
            assert_eq!(summary.metric.total.values.len(),10);
            assert_eq!(summary.metric.total.percentile(50),Some(p50),"{axis:?}");
            assert_eq!(summary.metric.total.histogram(16).iter().map(|b|b.count).sum::<usize>(),10);
            assert_eq!(summary.metric.read.values.len(),5);
            assert_eq!(summary.metric.write.values.len(),5);
        }
    }

    #[test]
    fn graph_summary_selection_filter_and_csv_share_the_same_values() {
        let engine=fixture(10);
        let filtered=engine.select_completed(|io|io.issue.operation==IoOperation::Write);
        let s=compute_selection(&filtered,SelectionRequest::Rectangle{min:[3.,0.],max:[7.,f64::INFINITY]},AxisMetric::TimeMs,AxisMetric::Sector,0);
        assert_eq!(s.keys.len(),2);
        assert_eq!(s.metric.total.values,[32.,48.]);
        assert_eq!(s.metric.read.values.len(),0);
        assert_eq!(s.address_counts.len(),2);
        let path=std::env::temp_dir().join(format!("graph-summary-{}.csv",uuid::Uuid::new_v4()));
        write_graph_summary_csv(&path,&s).unwrap();
        let mut reader=csv::Reader::from_path(&path).unwrap();
        let records=reader.records().collect::<Result<Vec<_>,_>>().unwrap();
        assert!(records.iter().any(|r| &r[0]=="percentile" && &r[2]=="8:0/Write" && &r[3]=="50" && &r[5]=="32"));
        assert_eq!(records.iter().filter(|r| &r[0]=="histogram" && &r[2]=="8:0/Total").map(|r|r[5].parse::<usize>().unwrap()).sum::<usize>(),2);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn summary_cancellation_invalidating_a_filter_signals_the_running_worker() {
        let mut app=StudioApp {analyzer:fixture(4),..Default::default()};
        app.poll_graph_summary();
        let cancelled=Arc::clone(&app.selection.all_pending.as_ref().unwrap().3.cancelled);
        app.query.pid=999;
        app.invalidate_query();
        assert!(cancelled.load(Ordering::Relaxed),"discarded receiver must stop obsolete aggregation, not just hide its result");
    }
    #[test]
    fn summary_cancellation_never_publishes_a_partial_or_empty_result() {
        let cancelled=AtomicBool::new(true);
        let result=compute_selection_cancellable(&fixture(4),SelectionRequest::Rectangle{min:[f64::NEG_INFINITY;2],max:[f64::INFINITY;2]},AxisMetric::TimeMs,AxisMetric::ChunkKiB,0,Some(&cancelled));
        assert!(result.is_none(),"cancelled work must not produce an apparent completed summary");
    }
    #[test]
    fn graph_summary_invalidates_on_filter_reset_and_axis_change() {
        let mut app=StudioApp {analyzer:fixture(4),..Default::default()};
        let all=SelectionRequest::Rectangle{min:[f64::NEG_INFINITY;2],max:[f64::INFINITY;2]};
        let s=compute_selection(&app.analyzer,all,app.x_axis,app.y_axis,0);
        app.selection.all_summary=Some((app.analysis_generation,app.x_axis,app.y_axis,s));
        app.query.process="no-such-process".into();
        app.invalidate_query();app.rebuild_filtered();
        assert!(app.selection.all_summary.is_none());
        assert!(app.analysis().completed_ios().is_empty());
        app.query=AnalysisFilter::default();app.invalidate_query();app.rebuild_filtered();
        assert_eq!(app.analysis().completed_ios().len(),4);
        app.y_axis=AxisMetric::ChunkKiB;
        app.poll_graph_summary();
        assert!(app.selection.all_summary.is_none());
        assert!(app.selection.all_pending.is_some());
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
        assert!(summary.is_none());

    }
}
