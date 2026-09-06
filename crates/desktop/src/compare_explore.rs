// Compare owns two offline viewers. Only their analysis/rendering methods run;
// neither viewer starts discovery, capture, persistence or application lifecycle.
// This reuses Explore's exact graph/selection/evidence semantics and keeps all
// request keys, inode mappings, filters and asynchronous results session-local.
struct CompareExplore {
    current: Option<Box<StudioApp>>,
    generation: Option<u64>,
    pending: Option<Receiver<Result<(PathBuf, session::LoadedAnalysis), String>>>,
    cancel: Option<Arc<AtomicBool>>,
    error: Option<String>,
    shared: AnalysisFilter,
    local: [AnalysisFilter; 2],
    applied: [AnalysisFilter; 2],
    linked_bounds: bool,
    same_rectangle: bool,
    preset: ExplorerPreset,
    axes: [AxisMetric; 2],
    category: GroupBy,
    style: PlotStyle,
    tab: CompareTab,
    needs_apply: bool,
    fit: bool,
    actions: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CompareTab {
    Metrics,
    Files,
    Processes,
    Distributions,
    Details,
}

impl Default for CompareExplore {
    fn default() -> Self {
        Self {
            current: None,
            generation: None,
            pending: None,
            cancel: None,
            error: None,
            shared: AnalysisFilter::default(),
            local: Default::default(),
            applied: Default::default(),
            linked_bounds: true,
            same_rectangle: false,
            preset: ExplorerPreset::LatencyTimeline,
            axes: [AxisMetric::TimeMs, AxisMetric::TotalLatencyMs],
            category: GroupBy::Direction,
            style: PlotStyle::default(),
            tab: CompareTab::Metrics,
            needs_apply: true,
            fit: true,
            actions: 0,
        }
    }
}

impl Drop for CompareExplore {
    fn drop(&mut self) {
        if let Some(cancel) = &self.cancel {
            cancel.store(true, Ordering::Relaxed);
        }
    }
}

fn compare_filter(shared: &AnalysisFilter, local: &AnalysisFilter) -> AnalysisFilter {
    AnalysisFilter {
        start_ms: shared.start_ms,
        end_ms: shared.end_ms,
        operation: shared.operation,
        confidence: shared.confidence,
        process: shared.process.clone(),
        file: local.file.clone(),
        device: local.device.clone(),
        pid: local.pid,
        tid: local.tid,
        // A request key is meaningful in exactly one session, never portable.
        request_keys: None,
    }
}

fn all_plot_requests() -> SelectionRequest {
    SelectionRequest::Rectangle {
        min: [f64::NEG_INFINITY; 2],
        max: [f64::INFINITY; 2],
    }
}

impl StudioApp {
    fn qa_compare_input(&mut self, raw: &mut egui::RawInput, gesture: &str) {
        if self.render_qa.frames < 28 || self.render_qa.frames < self.render_qa.range_wait_frame + 4
        {
            return;
        }
        let Some(baseline) = self.comparison.as_ref() else {
            return;
        };
        let Some(current) = self.compare_explore.current.as_ref() else {
            return;
        };
        if baseline.viewer.selection.pending.is_some() || current.selection.pending.is_some() {
            return;
        }
        let step = self.render_qa.input_step;
        if step >= 7 {
            return;
        }
        let first = baseline.viewer.selection.summary.as_ref();
        let second = current.selection.summary.as_ref();
        if step == 0 {
            self.render_qa.range_initial = baseline.viewer.selection.current_bounds;
            if gesture == "compare-area" {
                self.compare_explore.same_rectangle = true;
            }
            if gesture == "compare-filter" {
                self.compare_explore.shared.operation = Some(IoOperation::Read);
            }
            if gesture == "compare-empty" {
                self.compare_explore.local[0].file = "does-not-exist.fixture".into();
            }
        }
        if step == 3 && gesture != "compare-zoom-back" {
            let done = match gesture {
                "compare-point" => {
                    first.is_some_and(|s| s.keys.len() == 1)
                        && second
                            .is_some_and(|s| s.keys.len() == current.analyzer.completed_ios().len())
                }
                "compare-clear" => {
                    first.is_some_and(|s| s.keys.is_empty())
                        && second
                            .is_some_and(|s| s.keys.len() == current.analyzer.completed_ios().len())
                }
                "compare-area" => first.zip(second).is_some_and(|(a, b)| {
                    !a.keys.is_empty()
                        && !b.keys.is_empty()
                        && a.keys.len() < baseline.viewer.analyzer.completed_ios().len()
                }),
                "compare-filter" => {
                    baseline.viewer.query.operation == Some(IoOperation::Read)
                        && current.query.operation == Some(IoOperation::Read)
                }
                "compare-empty" => {
                    first.is_some_and(|s| s.keys.is_empty())
                        && second.is_some_and(|s| !s.keys.is_empty())
                }
                "compare-files" => self.compare_explore.tab == CompareTab::Files,
                "compare-processes" => self.compare_explore.tab == CompareTab::Processes,
                "compare-distributions" => self.compare_explore.tab == CompareTab::Distributions,
                "compare-details" => self.compare_explore.tab == CompareTab::Details,
                _ => false,
            };
            if done {
                self.render_qa.input_step = 7;
            }
            return;
        }
        if gesture == "compare-zoom-back" && step == 6 {
            if baseline
                .viewer
                .selection
                .current_bounds
                .zip(self.render_qa.range_initial)
                .is_some_and(|(a, b)| a.min() == b.min() && a.max() == b.max())
            {
                self.render_qa.input_step = 7;
            }
            return;
        }
        let pos = if gesture == "compare-area" {
            self.render_qa
                .regions
                .get("Compare Baseline graph")
                .map(|(r, _)| {
                    if step == 0 {
                        egui::pos2(r.left() + r.width() * 0.05, r.top() + r.height() * 0.20)
                    } else {
                        egui::pos2(r.left() + r.width() * 0.70, r.top() + r.height() * 0.85)
                    }
                })
        } else {
            let key = match gesture {
                "compare-point" => "Baseline point",
                "compare-clear" => "Baseline Clear",
                "compare-filter" | "compare-empty" => "Compare Apply",
                "compare-zoom-back" => {
                    if step < 3 {
                        "Baseline Zoom"
                    } else {
                        "Baseline Back"
                    }
                }
                "compare-files" => "Compare Files",
                "compare-processes" => "Compare Processes",
                "compare-distributions" => "Compare Distributions",
                "compare-details" => "Compare I/O details",
                _ => return,
            };
            self.render_qa.inspector_buttons.get(key).copied()
        };
        if let Some(pos) = pos {
            if step == 0
                && gesture != "compare-area"
                && self
                    .render_qa
                    .point_target
                    .is_none_or(|p| p.distance(pos) > 0.5)
            {
                self.render_qa.point_target = Some(pos);
                self.render_qa.range_wait_frame = self.render_qa.frames;
                return;
            }
            raw.events.push(egui::Event::PointerMoved(pos));
            if gesture == "compare-area" {
                if step == 0 || step == 2 {
                    raw.events.push(egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed: step == 0,
                        modifiers: Default::default(),
                    });
                }
            } else if !step.is_multiple_of(3) {
                raw.events.push(egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: step % 3 == 1,
                    modifiers: Default::default(),
                });
            }
            self.render_qa.input_step += 1;
            self.render_qa.range_wait_frame = self.render_qa.frames;
        }
    }

    fn compare_qa_report(&self) -> serde_json::Value {
        let describe = |v: &StudioApp| {
            serde_json::json!({
                "source":v.session_path,"origin_ns":v.time_origin(),"filter":v.query,
                "retained":v.analyzer.completed_ios().len(),"filtered":v.analysis().completed_ios().len(),
                "selected":v.selection.summary.as_ref().map(|s|s.keys.len()),
                "read_bytes":v.selection.summary.as_ref().map(|s|s.read.bytes),
                "write_bytes":v.selection.summary.as_ref().map(|s|s.write.bytes),
                "files":v.selection.summary.as_ref().map(|s|s.files.keys().collect::<Vec<_>>()),
                "processes":v.selection.summary.as_ref().map(|s|s.processes.keys().collect::<Vec<_>>()),
                "selection_wall_ms":v.selection.wall_ms,"selection_ms":v.selection.summary.as_ref().map(|s|s.elapsed.as_secs_f64()*1000.0),
                "bounds":v.selection.current_bounds.map(|b|[b.min(),b.max()]),
                "zoom_depth":v.selection.zoom_history.len(),
                "displayed":v.explorer_view.as_ref().map(|v|v.displayed),
                "axes":[v.x_axis.label(),v.y_axis.label()],"category":v.group_by.label(),
            })
        };
        serde_json::json!({"ready_ms":self.render_qa.compare_ready_ms,"baseline":self.comparison.as_ref().map(|b|describe(&b.viewer)),"current":self.compare_explore.current.as_ref().map(|b|describe(b)),"actions":self.compare_explore.actions,"linked":self.compare_explore.linked_bounds,"error":self.compare_explore.error})
    }

    fn comparison_viewer(&self) -> StudioApp {
        let mut view = StudioApp {
            analyzer: self.analyzer.select_completed(|_| true),
            session_path: self.session_path.clone(),
            capabilities: self.capabilities.clone(),
            rejected_records: self.rejected_records,
            loss_status: self.loss_status.clone(),
            phase: CapturePhase::Complete,
            analysis_generation: self.analysis_generation,
            plot_style: self.plot_style.clone(),
            page: Page::Explore,
            ..Default::default()
        };
        view.reanalysis.source_start_ns = Some(self.time_origin());
        view.reanalysis.source_end_ns = self.reanalysis.source_end_ns;
        view.reanalysis.source_count = self
            .reanalysis
            .source_count
            .max(self.analyzer.completed_ios().len() as u64);
        view.reanalysis.window = self.reanalysis.window;
        view
    }

    fn start_comparison_load(&mut self, path: PathBuf) {
        if self.compare_explore.pending.is_some() {
            return;
        }
        let (tx, rx) = bounded(1);
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = cancel.clone();
        self.compare_explore.pending = Some(rx);
        self.compare_explore.cancel = Some(cancel);
        self.compare_explore.error = None;
        std::thread::spawn(move || {
            let result = session::load_analysis_window(&path, None, Some(&worker_cancel))
                .map(|loaded| (path, loaded))
                .map_err(|e| e.to_string());
            let _ = tx.send(result);
        });
    }

    fn poll_comparison_load(&mut self) {
        let result = self
            .compare_explore
            .pending
            .as_ref()
            .and_then(|rx| match rx.try_recv() {
                Ok(result) => Some(result),
                Err(crossbeam_channel::TryRecvError::Disconnected) => Some(Err(
                    "Baseline loader stopped. Open the session again.".into(),
                )),
                Err(crossbeam_channel::TryRecvError::Empty) => None,
            });
        if let Some(result) = result {
            self.compare_explore.pending = None;
            self.compare_explore.cancel = None;
            match result {
                Ok((path, loaded)) => {
                    let mut viewer = StudioApp::default();
                    viewer.apply_loaded_session(path.clone(), loaded);
                    self.comparison = Some(ComparisonBaseline {
                        summary: viewer.analyzer.retained_summary(),
                        rejected_records: viewer.rejected_records,
                        capabilities: viewer.capabilities.clone(),
                        path,
                        viewer: Box::new(viewer),
                    });
                    self.compare_explore.needs_apply = true;
                    self.compare_explore.fit = true;
                    self.status = "Baseline loaded. Compare graphs and selected I/O below.".into();
                }
                Err(error) => self.compare_explore.error = Some(error),
            }
        }
    }

    fn compare_ui(&mut self, ui: &mut egui::Ui) {
        self.poll_comparison_load();
        section_header(
            ui,
            "Compare Explore",
            "Baseline and Current · same axes, separate session evidence",
        );
        ui.horizontal_wrapped(|ui| {
            let pin = ui.add_enabled(
                !self.is_running()
                    && !self.query.active()
                    && !self.analyzer.completed_ios().is_empty()
                    && self.compare_explore.pending.is_none(),
                egui::Button::new("Keep current as baseline"),
            );
            self.render_qa
                .inspector_buttons
                .insert("Keep baseline".into(), pin.rect.center());
            if pin.clicked() {
                self.pin_comparison();
                self.compare_explore.needs_apply = true;
            }
            if ui
                .add_enabled(
                    self.compare_explore.pending.is_none(),
                    egui::Button::new("Open baseline session"),
                )
                .clicked()
            {
                self.open_comparison_session();
            }
            if ui
                .add_enabled(
                    !self.is_running(),
                    egui::Button::new("Open current session"),
                )
                .clicked()
            {
                self.open_session();
            }
            if self.comparison.is_some() && ui.button("Clear baseline").clicked() {
                self.comparison = None;
                self.compare_explore.current = None;
                self.compare_explore.generation = None;
            }
        });
        if self.compare_explore.pending.is_some() {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Loading baseline… existing comparison preserved");
                if ui.button("Cancel load").clicked()
                    && let Some(cancel) = &self.compare_explore.cancel
                {
                    cancel.store(true, Ordering::Relaxed);
                }
            });
            ui.ctx().request_repaint_after(Duration::from_millis(30));
        }
        if let Some(error) = &self.compare_explore.error {
            ui.colored_label(red(), format!("Baseline not replaced: {error}"));
        }
        if self.is_running() {
            ui.label(
                "Stop & analyze to refresh Current. Offline comparison remains a stable snapshot.",
            );
        }
        if self.comparison.is_none() {
            ui.label("Keep this session as Baseline, then open or record another session as Current. Or open an earlier baseline file.");
            return;
        }
        if self.analyzer.completed_ios().is_empty() {
            ui.label("Current has no retained completed I/O. Open or record a session with request detail; device counters cannot provide scatter or selection metrics.");
            return;
        }
        if self.compare_explore.generation != Some(self.analysis_generation) && !self.is_running() {
            self.compare_explore.current = Some(Box::new(self.comparison_viewer()));
            self.compare_explore.generation = Some(self.analysis_generation);
            self.compare_explore.style = self.plot_style.clone();
            self.compare_explore.needs_apply = true;
            self.compare_explore.fit = true;
        }
        // Temporarily move this independent UI state to avoid aliasing the host.
        let mut state = std::mem::take(&mut self.compare_explore);
        let Some(mut current) = state.current.take() else {
            self.compare_explore = state;
            return;
        };
        let baseline = &mut self.comparison.as_mut().expect("baseline checked").viewer;
        compare_controls(ui, &mut state, baseline, &mut current, &mut self.render_qa);
        if state.needs_apply {
            compare_apply(&mut state, baseline, &mut current);
        }
        baseline.poll_selection();
        current.poll_selection();
        if self.render_qa.compare_ready_ms.is_none()
            && baseline.selection.pending.is_none()
            && current.selection.pending.is_none()
        {
            self.render_qa.compare_ready_ms = self
                .render_qa
                .started
                .map(|t| t.elapsed().as_secs_f64() * 1000.0);
        }
        if baseline.selection.pending.is_some() || current.selection.pending.is_some() {
            ui.ctx().request_repaint_after(Duration::from_millis(20));
        }
        if state.fit {
            compare_fit(baseline, &mut current, state.linked_bounds);
            state.fit = false;
        }
        ui.small("Time = completion relative to each source origin. Linked bounds change the view, not the population. PIDs, devices and file identities stay session-local.");
        let width = ui.available_width();
        if width >= 1080.0 {
            let height = (ui.clip_rect().bottom() - ui.cursor().top() - 12.0).max(320.0);
            let gap = 16.0;
            let summary_width = (width * 0.38).clamp(430.0, 500.0);
            let graph_width = width - summary_width - gap;
            ui.horizontal_top(|ui| {
                let graphs = ui.allocate_ui_with_layout(
                    egui::vec2(graph_width, height),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        egui::ScrollArea::vertical()
                            .id_salt("compare-graphs-scroll")
                            .max_height(height)
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                compare_graphs(
                                    ui,
                                    &mut state,
                                    baseline,
                                    &mut current,
                                    &mut self.render_qa,
                                );
                            });
                    },
                );
                ui.add_space(gap - ui.spacing().item_spacing.x);
                let summary = ui.allocate_ui_with_layout(
                    egui::vec2(summary_width, height),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        egui::Frame::new()
                            .fill(panel())
                            .inner_margin(10.0)
                            .stroke(Stroke::new(1.0, border()))
                            .show(ui, |ui| {
                                egui::ScrollArea::vertical()
                                    .id_salt("compare-summary-scroll")
                                    .max_height(height - 20.0)
                                    .auto_shrink([false, false])
                                    .show(ui, |ui| {
                                        compare_summary_ui(
                                            ui,
                                            &mut state,
                                            baseline,
                                            &mut current,
                                            &mut self.render_qa,
                                            &self.tx,
                                        );
                                    });
                            });
                    },
                );
                qa_region(
                    &mut self.render_qa,
                    "Compare graphs viewport",
                    graphs.response.rect,
                    ui.clip_rect(),
                );
                qa_region(
                    &mut self.render_qa,
                    "Compare summary viewport",
                    summary.response.rect,
                    ui.clip_rect(),
                );
            });
        } else {
            compare_graphs(ui, &mut state, baseline, &mut current, &mut self.render_qa);
            ui.separator();
            compare_summary_ui(
                ui,
                &mut state,
                baseline,
                &mut current,
                &mut self.render_qa,
                &self.tx,
            );
        }
        state.current = Some(current);
        self.plot_style = state.style.clone();
        self.compare_explore = state;
        ui.collapsing("Whole-session totals (legacy comparison)", |ui| {
            self.compare_totals_ui(ui);
        });
    }
}

fn compare_graphs(
    ui: &mut egui::Ui,
    state: &mut CompareExplore,
    baseline: &mut StudioApp,
    current: &mut StudioApp,
    qa: &mut RenderQa,
) {
    let mut requests = [None, None];
    if ui.available_width() >= 640.0 {
        ui.columns(2, |cols| {
            requests[0] = compare_pane(&mut cols[0], baseline, "Baseline", qa);
            if state.linked_bounds {
                copy_bounds(baseline, current);
            }
            requests[1] = compare_pane(&mut cols[1], current, "Current", qa);
        });
    } else {
        requests[0] = compare_pane(ui, baseline, "Baseline", qa);
        if state.linked_bounds {
            copy_bounds(baseline, current);
        }
        ui.separator();
        requests[1] = compare_pane(ui, current, "Current", qa);
    }
    if state.linked_bounds {
        copy_bounds(current, baseline);
    }
    if state.same_rectangle {
        if let Some(request @ SelectionRequest::Rectangle { .. }) = requests[0] {
            current.begin_selection(request);
        }
        if let Some(request @ SelectionRequest::Rectangle { .. }) = requests[1] {
            baseline.begin_selection(request);
        }
    }
}

fn compare_summary_ui(
    ui: &mut egui::Ui,
    state: &mut CompareExplore,
    baseline: &mut StudioApp,
    current: &mut StudioApp,
    qa: &mut RenderQa,
    tx: &crossbeam_channel::Sender<HostMessage>,
) {
    ui.heading("Selection Summary");
    if ui
        .add_enabled(
            baseline.selection.pending.is_none()
                && current.selection.pending.is_none()
                && baseline.selection.summary.is_some()
                && current.selection.summary.is_some(),
            egui::Button::new("Export comparison JSON"),
        )
        .clicked()
        && let Some(path) = rfd::FileDialog::new()
            .set_file_name("storage-session-comparison.json")
            .add_filter("Comparison JSON", &["json"])
            .save_file()
    {
        let payload = compare_export_payload(baseline, current);
        let sources = [baseline.session_path.clone(), current.session_path.clone()];
        let tx = tx.clone();
        std::thread::spawn(move || {
            let result = write_compare_export(&path, &sources, payload)
                .map(|_| path)
                .map_err(|e| e.to_string());
            let _ = tx.send(HostMessage::ViewExported(result));
        });
    }
    ui.small("Delta = Current − Baseline. Different request mixes or recording durations do not establish a performance improvement.");
    ui.horizontal_wrapped(|ui| {
        for (tab, name) in [
            (CompareTab::Metrics, "Summary"),
            (CompareTab::Files, "Files"),
            (CompareTab::Processes, "Processes"),
            (CompareTab::Distributions, "Distributions"),
            (CompareTab::Details, "I/O details"),
        ] {
            let r = ui.selectable_value(&mut state.tab, tab, name);
            qa.inspector_buttons
                .insert(format!("Compare {name}"), r.rect.center());
            if qa.output.is_some()
                && qa.input_step == 0
                && qa.frames >= 28
                && !ui.clip_rect().contains(r.rect.center())
                && std::env::var("ANDROID_EBPF_QA_GESTURE").is_ok_and(|s| {
                    matches!(
                        (s.as_str(), name),
                        ("compare-files", "Files")
                            | ("compare-processes", "Processes")
                            | ("compare-distributions", "Distributions")
                            | ("compare-details", "I/O details")
                    )
                })
            {
                r.scroll_to_me(Some(egui::Align::TOP));
            }
        }
    });
    if baseline.selection.pending.is_some() || current.selection.pending.is_some() {
        ui.label("Calculating exact selection summaries… Previous values are hidden until both sides finish.");
    } else if let Some((a, b)) = baseline
        .selection
        .summary
        .as_ref()
        .zip(current.selection.summary.as_ref())
    {
        match state.tab {
            CompareTab::Metrics => compare_metrics(ui, a, b),
            CompareTab::Files | CompareTab::Processes => {
                let tab = if state.tab == CompareTab::Files {
                    InspectorTab::Files
                } else {
                    InspectorTab::Processes
                };
                compare_target_columns(ui, a, b, tab);
            }
            CompareTab::Distributions => compare_distributions(ui, a, b),
            CompareTab::Details => compare_details(ui, baseline, current),
        }
    } else {
        ui.label(
            "Select points/areas in each graph or use Select all filtered to compare populations.",
        );
    }
    ui.collapsing("Source quality & comparison definitions", |ui| {
            for (label,v) in [("Baseline",&*baseline),("Current",&*current)] {
                ui.strong(label); ui.label(format!("{} · {} rejected records",v.loss_status,v.rejected_records));
                ui.label(format!("{} retained I/O / {} source completed I/O · origin {} ns · loaded window {:?}",v.analyzer.completed_ios().len(),v.reanalysis.source_count,v.time_origin(),v.reanalysis.window));
            }
            ui.label("Area selection includes all plottable requests under the applied filters, even if points are sampled. Unsupported axis values are excluded, never zero-filled. Access patterns retain original device/direction issue order. Candidate file bytes overlap and are not additive. Baseline is kept in memory; save sessions to reopen after app restart.");
        });
}

fn compare_controls(
    ui: &mut egui::Ui,
    state: &mut CompareExplore,
    a: &mut StudioApp,
    b: &mut StudioApp,
    qa: &mut RenderQa,
) {
    let old_axes = state.axes;
    ui.horizontal_wrapped(|ui| {
        let old=state.preset;
        egui::ComboBox::from_id_salt("compare-preset").selected_text(state.preset.label()).show_ui(ui,|ui| {
            for preset in ExplorerPreset::ALL { ui.selectable_value(&mut state.preset,preset,preset.label()); }
        });
        if old!=state.preset && let Some((x,y,group))=state.preset.query() {state.axes=[x,y];state.category=group;}
        ui.checkbox(&mut state.linked_bounds,"Link X/Y view");
        ui.checkbox(&mut state.same_rectangle,"Select same area in both").on_hover_text("Rectangle coordinates are applied separately to both sessions. Clicking one point never selects an unrelated request on the other side.");
        let r=ui.button("Fit both");qa.inspector_buttons.insert("Compare Fit".into(),r.rect.center());
        if r.clicked(){state.fit=true;}
    });
    ui.collapsing("Axes, colors & point size", |ui| {
        ui.horizontal_wrapped(|ui| {
            axis_combo(ui, "compare-x", "X", &mut state.axes[0]);
            axis_combo(ui, "compare-y", "Y", &mut state.axes[1]);
            egui::ComboBox::from_id_salt("compare-category")
                .selected_text(state.category.label())
                .show_ui(ui, |ui| {
                    for group in GroupBy::ALL {
                        ui.selectable_value(&mut state.category, group, group.label());
                    }
                });
            ui.add(
                egui::Slider::new(&mut state.style.point_diameter, 2.0..=20.0)
                    .text("Point size (px)"),
            );
        });
        b.group_by = state.category;
        b.plot_style = state.style.clone();
        let names: Vec<_> = a
            .explorer_view
            .iter()
            .chain(b.explorer_view.iter())
            .flat_map(|v| v.groups.iter().map(|(n, _)| n.clone()))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        b.plot_colors_ui(ui, &names);
        state.style = b.plot_style.clone();
    });
    if old_axes != state.axes {
        for v in [&mut *a, &mut *b] {
            v.x_axis = state.axes[0];
            v.y_axis = state.axes[1];
            v.selection = SelectionState {
                enabled: true,
                auto_bounds: true,
                ..Default::default()
            };
            v.begin_selection(all_plot_requests());
        }
        state.fit = true;
    }
    for v in [&mut *a, &mut *b] {
        v.x_axis = state.axes[0];
        v.y_axis = state.axes[1];
        v.group_by = state.category;
        v.plot_style = state.style.clone();
    }
    egui::CollapsingHeader::new("Comparison filters · apply to both sessions")
        .open(
            (qa.output.is_some()
                && std::env::var("ANDROID_EBPF_QA_GESTURE")
                    .is_ok_and(|s| s == "compare-filter" || s == "compare-empty"))
            .then_some(true),
        )
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label("Completion time (ms):");
                ui.add(
                    egui::DragValue::new(&mut state.shared.start_ms)
                        .range(0.0..=1e15)
                        .prefix("Start "),
                );
                ui.add(
                    egui::DragValue::new(&mut state.shared.end_ms)
                        .range(0.0..=1e15)
                        .prefix("End "),
                );
                ui.small("End 0 = open");
                egui::ComboBox::from_id_salt("compare-op")
                    .selected_text(
                        state
                            .shared
                            .operation
                            .map_or("All operations", operation_label),
                    )
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut state.shared.operation, None, "All operations");
                        for op in [IoOperation::Read, IoOperation::Write] {
                            ui.selectable_value(
                                &mut state.shared.operation,
                                Some(op),
                                operation_label(op),
                            );
                        }
                    });
                egui::ComboBox::from_id_salt("compare-confidence")
                    .selected_text(
                        state
                            .shared
                            .confidence
                            .map_or("All confidence".into(), |c| format!("{c:?}")),
                    )
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut state.shared.confidence, None, "All confidence");
                        for c in [
                            PathConfidence::Exact,
                            PathConfidence::Probable,
                            PathConfidence::Unresolved,
                        ] {
                            ui.selectable_value(
                                &mut state.shared.confidence,
                                Some(c),
                                format!("{c:?}"),
                            );
                        }
                    });
            });
            ui.horizontal_wrapped(|ui| {
                ui.label("Process name contains (both)");
                ui.text_edit_singleline(&mut state.shared.process);
            });
            for (i, label) in ["Baseline", "Current"].into_iter().enumerate() {
                ui.push_id(label, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.strong(label);
                        let q = &mut state.local[i];
                        ui.add(egui::DragValue::new(&mut q.pid).prefix("PID "));
                        ui.add(egui::DragValue::new(&mut q.tid).prefix("TID "));
                        ui.add(
                            egui::TextEdit::singleline(&mut q.file)
                                .hint_text("File contains")
                                .desired_width(150.0),
                        );
                        ui.add(
                            egui::TextEdit::singleline(&mut q.device)
                                .hint_text("Device major:minor")
                                .desired_width(130.0),
                        );
                    });
                });
            }
            ui.horizontal_wrapped(|ui| {
                let r = ui.button("Apply comparison filters");
                qa.inspector_buttons
                    .insert("Compare Apply".into(), r.rect.center());
                if qa.output.is_some()
                    && qa.input_step < 3
                    && std::env::var("ANDROID_EBPF_QA_GESTURE")
                        .is_ok_and(|s| s == "compare-filter" || s == "compare-empty")
                {
                    r.scroll_to_me(Some(egui::Align::Center));
                }
                if r.clicked() {
                    if state.shared.end_ms > 0.0 && state.shared.end_ms < state.shared.start_ms {
                        state.error =
                            Some("Filter End must be at least Start (or 0 for open).".into());
                    } else {
                        state.needs_apply = true;
                        state.fit = true;
                        state.error = None;
                    }
                }
                let r = ui.button("Reset comparison filters");
                qa.inspector_buttons
                    .insert("Compare Reset".into(), r.rect.center());
                if r.clicked() {
                    state.shared = Default::default();
                    state.local = Default::default();
                    state.needs_apply = true;
                    state.fit = true;
                    state.error = None;
                }
            });
        });
    let draft = [
        compare_filter(&state.shared, &state.local[0]),
        compare_filter(&state.shared, &state.local[1]),
    ];
    if draft != state.applied {
        ui.colored_label(amber(), "Filter edits are not applied yet.");
    }
    ui.small(format!(
        "Applied: {:.1}–{} ms · {} · process '{}' · confidence {}",
        state.applied[0].start_ms,
        if state.applied[0].end_ms == 0.0 {
            "end".into()
        } else {
            format!("{:.1}", state.applied[0].end_ms)
        },
        state.applied[0]
            .operation
            .map_or("All operations", operation_label),
        state.applied[0].process,
        state.applied[0]
            .confidence
            .map_or("All".into(), |c| format!("{c:?}"))
    ));
}

fn compare_apply(state: &mut CompareExplore, a: &mut StudioApp, b: &mut StudioApp) {
    for (i, v) in [a, b].into_iter().enumerate() {
        let query = compare_filter(&state.shared, &state.local[i]);
        state.applied[i] = query.clone();
        v.query = query;
        v.invalidate_query();
        v.rebuild_filtered();
        v.begin_selection(all_plot_requests());
    }
    state.actions += 1;
    state.needs_apply = false;
}

fn compare_fit(a: &mut StudioApp, b: &mut StudioApp, linked: bool) {
    a.rebuild_explorer_view();
    b.rebuild_explorer_view();
    if !linked {
        a.selection.fit_axis_ranges();
        b.selection.fit_axis_ranges();
        return;
    }
    let mut bounds = egui_plot::PlotBounds::NOTHING;
    for v in [&*a, &*b] {
        for p in v
            .explorer_view
            .iter()
            .flat_map(|v| &v.groups)
            .flat_map(|(_, p)| p)
        {
            bounds.extend_with(&egui_plot::PlotPoint::new(
                p.coordinates[0],
                p.coordinates[1],
            ));
        }
    }
    if bounds
        .min()
        .iter()
        .chain(bounds.max().iter())
        .all(|v| v.is_finite())
    {
        let min = bounds.min();
        let max = bounds.max();
        let pad = [
            (max[0] - min[0]).abs().max(0.001) * 0.05,
            (max[1] - min[1]).abs().max(0.001) * 0.05,
        ];
        let bounds = egui_plot::PlotBounds::from_min_max(
            [min[0] - pad[0], min[1] - pad[1]],
            [max[0] + pad[0], max[1] + pad[1]],
        );
        for v in [a, b] {
            v.selection.remember_view();
            v.selection.bounds_command = Some(bounds);
            v.selection.auto_bounds = false;
        }
    }
}

fn copy_bounds(from: &StudioApp, to: &mut StudioApp) {
    if let Some(bounds) = from.selection.current_bounds {
        let different = to
            .selection
            .current_bounds
            .is_none_or(|b| b.min() != bounds.min() || b.max() != bounds.max());
        if different && to.selection.bounds_command.is_none() {
            to.selection.bounds_command = Some(bounds);
            to.selection.auto_bounds = false;
        }
    }
}

fn compare_pane(
    ui: &mut egui::Ui,
    v: &mut StudioApp,
    label: &str,
    qa: &mut RenderQa,
) -> Option<SelectionRequest> {
    ui.push_id(("compare-pane", label), |ui| {
        ui.strong(label);
        ui.add(
            egui::Label::new(
                v.session_path
                    .as_ref()
                    .and_then(|p| p.file_name())
                    .map_or("Unsaved session".into(), |s| {
                        s.to_string_lossy().to_string()
                    }),
            )
            .truncate(),
        )
        .on_hover_text(
            v.session_path
                .as_ref()
                .map_or(String::new(), |p| p.display().to_string()),
        );
        ui.horizontal_wrapped(|ui| {
            ui.selectable_value(&mut v.selection.enabled, true, "Select");
            ui.selectable_value(&mut v.selection.enabled, false, "Pan");
            for action in ["Select all filtered", "Zoom", "Back", "Clear"] {
                let enabled = match action {
                    "Zoom" => {
                        v.selection
                            .summary
                            .as_ref()
                            .is_some_and(|s| !s.keys.is_empty())
                            && v.selection.pending.is_none()
                    }
                    "Back" => !v.selection.zoom_history.is_empty(),
                    _ => true,
                };
                let r = ui.add_enabled(enabled, egui::Button::new(action));
                qa.inspector_buttons
                    .insert(format!("{label} {action}"), r.rect.center());
                if r.clicked() {
                    match action {
                        "Select all filtered" => v.begin_selection(all_plot_requests()),
                        "Zoom" => {
                            v.selection.remember_view();
                            if let Some(bounds) =
                                v.selection.summary.as_ref().and_then(|s| s.bounds)
                            {
                                let min = bounds.min();
                                let max = bounds.max();
                                let pad = [
                                    (max[0] - min[0]).abs().max(0.001) * 0.05,
                                    (max[1] - min[1]).abs().max(0.001) * 0.05,
                                ];
                                v.selection.bounds_command =
                                    Some(egui_plot::PlotBounds::from_min_max(
                                        [min[0] - pad[0], min[1] - pad[1]],
                                        [max[0] + pad[0], max[1] + pad[1]],
                                    ));
                                v.selection.auto_bounds = false;
                            }
                        }
                        "Back" => v.selection.bounds_command = v.selection.zoom_history.pop(),
                        _ => {
                            v.selection.summary = Some(SelectionSummary::default());
                            v.selection.queued = None;
                            v.selection.discard_pending = true;
                        }
                    }
                }
            }
        });
        ui.collapsing("Manual X/Y range", |ui| v.axis_ranges_ui(ui));
        let request = v.explorer_plot_ui(ui, true);
        if let Some(rect) = v.render_qa.plot_rect {
            qa.regions
                .insert(format!("Compare {label} graph"), (rect, ui.clip_rect()));
        }
        if let Some(point) = v.render_qa.point_target {
            qa.inspector_buttons.insert(format!("{label} point"), point);
            // The native QA click must target visible content. At high scale the
            // narrow layout scrolls; an off-screen point cannot receive a click.
            if qa.output.is_some()
                && qa.input_step == 0
                && label == "Baseline"
                && !ui.clip_rect().contains(point)
                && std::env::var("ANDROID_EBPF_QA_GESTURE").is_ok_and(|s| s == "compare-point")
            {
                ui.scroll_to_rect(
                    egui::Rect::from_center_size(point, egui::vec2(12.0, 12.0)),
                    None,
                );
            }
        }
        if v.selection.pending.is_some() {
            ui.label("Selection calculating…");
        } else if let Some(s) = &v.selection.summary {
            ui.label(format!(
                "{} selected · R {} / W {} · span {}",
                s.keys.len(),
                format_bytes(s.read.bytes),
                format_bytes(s.write.bytes),
                format_latency(s.duration_ns())
            ));
        }
        ui.small(format!(
            "Local filter: PID {} · TID {} · device '{}' · file '{}'",
            v.query.pid, v.query.tid, v.query.device, v.query.file
        ));
        request
    })
    .inner
}

fn compare_metrics(ui: &mut egui::Ui, a: &SelectionSummary, b: &SelectionSummary) {
    egui::ScrollArea::horizontal()
        .id_salt("compare-metrics-scroll")
        .show(ui, |ui| {
            egui::Grid::new("compare-selected-metrics")
                .striped(true)
                .min_col_width(58.0)
                .spacing(egui::vec2(10.0, 6.0))
                .show(ui, |ui| {
                    for h in ["Metric", "Baseline", "Current", "Delta"] {
                        ui.strong(h);
                    }
                    ui.end_row();
                    comparison_row(
                        ui,
                        "Data Count",
                        a.keys.len() as u64,
                        b.keys.len() as u64,
                        |v| v.to_string(),
                    );
                    comparison_optional_latency_row(
                        ui,
                        "End − Start",
                        a.duration_ns(),
                        b.duration_ns(),
                    );
                    for (label, x, y) in [("Read", &a.read, &b.read), ("Write", &a.write, &b.write)]
                    {
                        comparison_row(ui, &format!("{label} count"), x.count, y.count, |v| {
                            v.to_string()
                        });
                        comparison_row(
                            ui,
                            &format!("{label} size"),
                            x.bytes,
                            y.bytes,
                            format_bytes,
                        );
                        ui.label(format!("{label} MiB/s"));
                        let av = a.throughput(x.bytes);
                        let bv = b.throughput(y.bytes);
                        for value in [av, bv, bv.zip(av).map(|(b, a)| b - a)] {
                            ui.monospace(value.map_or("—".into(), |v| format!("{v:.3}")));
                        }
                        ui.end_row();
                    }
                    comparison_row(ui, "Other operations", a.other_count, b.other_count, |v| {
                        v.to_string()
                    });
                });
        });
    ui.collapsing("Read / Write latency percentiles", |ui| {
        egui::ScrollArea::horizontal()
            .id_salt("compare-timing-scroll")
            .show(ui, |ui| {
                egui::Grid::new("compare-timing")
                    .striped(true)
                    .spacing(egui::vec2(10.0, 6.0))
                    .show(ui, |ui| {
                        for h in ["Metric", "Baseline", "Current", "Delta"] {
                            ui.strong(h);
                        }
                        ui.end_row();
                        for (label, x, y) in
                            [("Read", &a.read, &b.read), ("Write", &a.write, &b.write)]
                        {
                            comparison_row(
                                ui,
                                &format!("{label} timed count"),
                                x.latency.len() as u64,
                                y.latency.len() as u64,
                                |v| v.to_string(),
                            );
                            for p in [50, 90, 95, 99, 100] {
                                comparison_optional_latency_row(
                                    ui,
                                    &format!(
                                        "{label} {}",
                                        if p == 100 {
                                            "Max".into()
                                        } else {
                                            format!("P{p}")
                                        }
                                    ),
                                    x.percentile(p),
                                    y.percentile(p),
                                );
                            }
                        }
                    });
            });
    });
    ui.small("Latency: insert (or issue) to completion; exact nearest-rank percentiles. MiB/s uses each selection's earliest known insert/issue (completion if unavailable) to latest completion span. Unknown pre-completion time is excluded. Percentiles include valid timing samples only. Empty/zero-span values are unavailable (—). No event pairing or file identity equivalence is implied.");
}

fn compare_export_payload(a: &StudioApp, b: &StudioApp) -> serde_json::Value {
    let describe = |v: &StudioApp| {
        let s = v
            .selection
            .summary
            .as_ref()
            .expect("selection required for export");
        let direction = |d: &DirectionSummary| serde_json::json!({"count":d.count,"bytes":d.bytes,"MiB_per_s":s.throughput(d.bytes),"chunk_counts":d.chunks,"valid_timing_samples":d.latency.len(),"unmeasured_timing_count":d.count-d.latency.len() as u64,"latency_ns": ([50,90,95,99,100].map(|p|serde_json::json!({"percentile":p,"value":d.percentile(p)})))});
        serde_json::json!({"source":v.session_path,"origin_ns":v.time_origin(),"retained_source_window_ns":v.reanalysis.window,"filters":v.query,"axes":[v.x_axis.label(),v.y_axis.label()],"bounds":v.selection.current_bounds.map(|b|[b.min(),b.max()]),"count":s.keys.len(),"selected_request_keys":s.keys,"start_ns":s.start_ns,"end_ns":s.end_ns,"span_ns":s.duration_ns(),"read":direction(&s.read),"write":direction(&s.write),"other_count":s.other_count,"other_bytes":s.other_bytes,"access_counts_random_sequential_unknown":s.access,"multiple_candidate_requests":s.multiple_candidates,"files":s.files.iter().map(|((path,identity,confidence),r)|serde_json::json!({"path":path,"identity":identity,"confidence":confidence,"count":r.count,"read_bytes":r.read_bytes,"write_bytes":r.write_bytes,"processes":r.processes})).collect::<Vec<_>>(),"processes":s.processes.iter().map(|((pid,tid,name),r)|serde_json::json!({"pid":pid,"tid":tid,"name":name,"count":r.count,"read_bytes":r.read_bytes,"write_bytes":r.write_bytes,"files":r.files})).collect::<Vec<_>>(),"loss":v.loss_status,"rejected_records":v.rejected_records})
    };
    serde_json::json!({"format":"android-ebpf-comparison","version":1,"scope":"independent exact selections from retained completed block I/O; graph sampling does not sample statistics","definitions":{"time":"completion relative to each source origin","latency":"insert or issue to completion; exact nearest-rank percentiles","throughput":"bytes divided by selected earliest known insert/issue (completion if unavailable) to latest completion span; MiB/s; unknown pre-completion time is excluded","missing":"null; no normal values inferred","files":"candidate bytes may overlap; identities are local to their source session","access":"original device/direction issue order"},"baseline":describe(a),"current":describe(b)})
}

fn write_compare_export(
    path: &std::path::Path,
    sources: &[Option<PathBuf>; 2],
    payload: serde_json::Value,
) -> anyhow::Result<()> {
    for source in sources.iter().flatten() {
        session::ensure_distinct_export(source, path)?;
    }
    let file = std::fs::File::create(path)?;
    let mut writer = std::io::BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, &payload)?;
    use std::io::Write;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    Ok(())
}

fn compare_target_columns(
    ui: &mut egui::Ui,
    a: &SelectionSummary,
    b: &SelectionSummary,
    tab: InspectorTab,
) {
    ui.small("Observed block issuer, not necessarily the application that dirtied cached data. Candidate bytes overlap; do not sum them as attributed file bytes.");
    let pane = |ui: &mut egui::Ui, label: &str, s: &SelectionSummary| {
        ui.push_id(("compare-targets", label), |ui| {
            ui.strong(label);
            let count = if tab == InspectorTab::Files {
                s.files.len()
            } else {
                s.processes.len()
            };
            ui.small(format!(
                "{count} entries · {} requests with multiple file candidates",
                s.multiple_candidates
            ));
            let page = target_page(ui, "compare-target-page", count);
            egui::ScrollArea::vertical()
                .id_salt("compare-target-scroll")
                .max_height(360.0)
                .min_scrolled_height(240.0)
                .show(ui, |ui| {
                    if tab == InspectorTab::Files {
                        for ((path, identity, confidence), row) in
                            s.files.iter().skip(page * 20).take(20)
                        {
                            ui.strong(path);
                            ui.small(format!("{identity} · {confidence}"));
                            target_metrics(ui, row);
                            ui.small(
                                row.processes
                                    .iter()
                                    .take(4)
                                    .map(|(pid, tid, name)| issuer_label(*pid, *tid, name))
                                    .collect::<Vec<_>>()
                                    .join(", "),
                            );
                            ui.separator();
                        }
                    } else {
                        for ((pid, tid, name), row) in s.processes.iter().skip(page * 20).take(20) {
                            ui.strong(issuer_label(*pid, *tid, name));
                            target_metrics(ui, row);
                            ui.collapsing(
                                format!("{} file evidence entries", row.files.len()),
                                |ui| {
                                    for file in &row.files {
                                        ui.label(file);
                                    }
                                },
                            );
                            ui.separator();
                        }
                    }
                });
        });
    };
    if ui.available_width() >= 1000.0 {
        ui.columns(2, |cols| {
            pane(&mut cols[0], "Baseline", a);
            pane(&mut cols[1], "Current", b);
        });
    } else {
        pane(ui, "Baseline", a);
        ui.separator();
        pane(ui, "Current", b);
    }
}

fn compare_distributions(ui: &mut egui::Ui, a: &SelectionSummary, b: &SelectionSummary) {
    for (label, s) in [("Baseline", a), ("Current", b)] {
        ui.push_id(("compare-distributions", label), |ui| {
            ui.strong(label);
            ui.vertical(|ui| {
                ui.vertical(|ui| {
                    ui.label("Random / Sequential · I/O count");
                    selection_pie(ui, &s.access, &["Random", "Sequential", "Unknown"]);
                });
                for (name, side) in [("Read", &s.read), ("Write", &s.write)] {
                    ui.vertical(|ui| {
                        ui.label(format!("{name} chunks · I/O count"));
                        selection_pie(
                            ui,
                            &side.chunks,
                            &["≤4 KiB", "4–16 KiB", "16–64 KiB", "64–256 KiB", ">256 KiB"],
                        );
                    });
                }
            });
        });
    }
}

fn compare_details(ui: &mut egui::Ui, a: &mut StudioApp, b: &mut StudioApp) {
    for (label, v) in [("Baseline", a), ("Current", b)] {
        ui.push_id(("compare-details",label),|ui| {
            ui.strong(label);
            if let Some(s)=&v.selection.summary {
                let rows:Vec<_>=v.analysis().completed_ios().iter().filter(|io|s.keys.contains(&selection_key(io))).collect();
                let page=target_page(ui,"compare-events",rows.len());
                for io in rows.into_iter().skip(page*20).take(20) {
                    ui.collapsing(format!("Request {} · {:.3} ms · {} · {} · PID {}/{}",io.issue.request_id,io.completion.ts_ns.saturating_sub(v.time_origin()) as f64/1e6,operation_label(io.issue.operation),format_bytes(io.issue.bytes as u64),identity_number(io.issuer_pid()),identity_number(io.issuer_tid())),|ui| {
                        ui.label(format!("{} · device {}:{} · sector {} · total {} · queue {} · issue-to-completion {}",io.issue.comm,io.issue.device_major,io.issue.device_minor,io.issue.sector,format_latency(io.total_latency_ns),format_latency(io.queue_latency_ns),format_latency(io.device_latency_ns)));
                        ui.label(file_origin_tooltip(&block_file_origins(&v.analysis().transaction_for(io))));
                    });
                }
            }
        });
    }
}

#[cfg(test)]
mod compare_explore_tests {
    use super::*;
    use android_ebpf_protocol::{BlockComplete, BlockIssue, StorageEvent};

    fn fixture(origin: u64, name: &str, pid: u32, device: u32, bytes: u32) -> StudioApp {
        let mut app = StudioApp::default();
        for id in 1..=8 {
            app.analyzer.ingest(StorageEvent::BlockIssue(BlockIssue {
                ts_ns: origin + id * 1_000_000,
                request_id: id,
                device_major: 8,
                device_minor: device,
                sector: id * 8,
                sectors: bytes / 512,
                bytes,
                operation: if id % 2 == 0 {
                    IoOperation::Write
                } else {
                    IoOperation::Read
                },
                pid,
                tid: pid + 1,
                cpu: 0,
                comm: name.into(),
            }));
            app.analyzer
                .ingest(StorageEvent::BlockComplete(BlockComplete {
                    ts_ns: origin + id * 1_000_000 + 500_000,
                    request_id: id,
                    device_major: 8,
                    device_minor: device,
                    status: 0,
                }));
        }
        app.reanalysis.source_start_ns = Some(origin);
        app.reanalysis.source_count = 8;
        app
    }

    #[test]
    fn equal_relative_area_uses_each_origin_and_keeps_issuer_and_device_evidence_separate() {
        let a = fixture(1_000_000_000, "alpha", 11, 0, 4096);
        let b = fixture(9_000_000_000, "beta", 22, 1, 8192);
        let area = SelectionRequest::Rectangle {
            min: [2.0, 0.0],
            max: [5.0, 10.0],
        };
        let sa = compute_selection(
            &a.analyzer,
            area,
            AxisMetric::TimeMs,
            AxisMetric::TotalLatencyMs,
            a.time_origin(),
        );
        let sb = compute_selection(
            &b.analyzer,
            area,
            AxisMetric::TimeMs,
            AxisMetric::TotalLatencyMs,
            b.time_origin(),
        );
        assert_eq!(sa.keys.len(), 3);
        assert_eq!(sb.keys.len(), 3);
        assert_eq!(sb.write.bytes, sa.write.bytes * 2);
        assert!(
            sa.processes
                .keys()
                .all(|(pid, _, name)| *pid == Some(11) && name == "alpha")
        );
        assert!(
            sb.processes
                .keys()
                .all(|(pid, _, name)| *pid == Some(22) && name == "beta")
        );
        assert!(sa.files.keys().all(|(_, id, _)| id.contains("8:0")));
        assert!(sb.files.keys().all(|(_, id, _)| id.contains("8:1")));
    }

    #[test]
    fn portable_filters_never_copy_request_keys_or_numeric_process_identity() {
        let shared = AnalysisFilter {
            pid: 11,
            tid: 12,
            device: "8:0".into(),
            request_keys: Some(Default::default()),
            operation: Some(IoOperation::Read),
            start_ms: 2.0,
            end_ms: 6.0,
            ..Default::default()
        };
        let local = AnalysisFilter {
            pid: 22,
            device: "8:1".into(),
            ..Default::default()
        };
        let q = compare_filter(&shared, &local);
        assert_eq!(q.pid, 22);
        assert_eq!(q.tid, 0);
        assert_eq!(q.device, "8:1");
        assert!(q.request_keys.is_none());
        let b = fixture(9_000_000_000, "beta", 22, 1, 8192);
        let selected = b
            .analyzer
            .select_completed(|io| q.matches(&b.analyzer, io, b.time_origin()));
        assert_eq!(selected.completed_ios().len(), 2);
    }

    #[test]
    fn pin_copies_complete_evidence_and_next_capture_cannot_mutate_baseline() {
        let mut app = fixture(1_000_000_000, "alpha", 11, 0, 4096);
        app.pin_comparison();
        app.analyzer = fixture(9_000_000_000, "beta", 22, 1, 8192).analyzer;
        app.reset_analysis();
        let baseline = &app.comparison.as_ref().unwrap().viewer;
        assert_eq!(baseline.analyzer.completed_ios().len(), 8);
        assert_eq!(baseline.time_origin(), 1_000_000_000);
        assert_eq!(baseline.analyzer.completed_ios()[0].issue.comm, "alpha");
    }

    #[test]
    fn missing_axes_and_empty_population_do_not_invent_percentiles_or_throughput() {
        let a = fixture(0, "alpha", 11, 0, 4096);
        let s = compute_selection(
            &a.analyzer,
            all_plot_requests(),
            AxisMetric::TimeMs,
            AxisMetric::QueueLatencyMs,
            0,
        );
        assert!(s.keys.is_empty());
        assert_eq!(s.read.percentile(95), None);
        assert_eq!(s.throughput(0), None);
    }

    #[test]
    fn applying_filters_discards_previous_async_selection_and_keeps_main_explore_unchanged() {
        let host = fixture(0, "alpha", 11, 0, 4096);
        let mut a = host.comparison_viewer();
        let mut b = fixture(9_000_000_000, "beta", 22, 1, 8192);
        a.begin_selection(all_plot_requests());
        let mut state = CompareExplore::default();
        state.shared.operation = Some(IoOperation::Write);
        compare_apply(&mut state, &mut a, &mut b);
        let deadline = Instant::now() + Duration::from_secs(3);
        while a.selection.pending.is_some() || b.selection.pending.is_some() {
            a.poll_selection();
            b.poll_selection();
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert_eq!(a.selection.summary.as_ref().unwrap().keys.len(), 4);
        assert_eq!(b.selection.summary.as_ref().unwrap().read.count, 0);
        assert_eq!(host.analyzer.completed_ios().len(), 8);
        assert!(!host.query.active());
    }

    #[test]
    fn baseline_load_failure_preserves_previous_source_and_reports_retryable_error() {
        let mut app = fixture(0, "alpha", 11, 0, 4096);
        app.pin_comparison();
        let (tx, rx) = bounded(1);
        app.compare_explore.pending = Some(rx);
        tx.send(Err("disk read failed".into())).unwrap();
        app.poll_comparison_load();
        assert!(
            app.compare_explore
                .error
                .as_ref()
                .unwrap()
                .contains("disk read failed")
        );
        assert_eq!(
            app.comparison
                .as_ref()
                .unwrap()
                .viewer
                .analyzer
                .completed_ios()
                .len(),
            8
        );
        assert!(app.compare_explore.pending.is_none());
    }

    #[test]
    fn compare_selection_preserves_unmeasured_perfetto_io_and_does_not_name_pid_zero() {
        let mut a = fixture(0, "alpha", 11, 0, 4096);
        let mut b = StudioApp::default();
        let mut io = a.analyzer.completed_ios()[0].clone();
        io.evidence = Some(Box::new(android_ebpf_protocol::CompletionEvidence {
            source: "Perfetto".into(),
            record_id: 1,
            issue_record_candidates: vec![],
            issue_timestamp_ns: None,
            issuer_pid: None,
            issuer_tid: None,
            issuer_cpu: None,
            completion_status: None,
            process_name: None,
            timing_confidence: android_ebpf_protocol::CorrelationConfidence::ContextOnly,
            reason: "No unique issue".into(),
            clock: 0,
        }));
        io.issue.pid = 0;
        io.issue.tid = 0;
        io.issue.comm = "<issuer unavailable>".into();
        io.issue.ts_ns = io.completion.ts_ns;
        io.total_latency_ns = None;
        io.device_latency_ns = None;
        io.latency_ns = None;
        io.queue_depth_after = None;
        io.access_pattern = android_ebpf_protocol::AccessPattern::Unknown;
        b.analyzer.ingest(StorageEvent::ObservedBlockCompletion(io));
        for app in [&mut a, &mut b] {
            app.selection.summary = Some(compute_selection(
                &app.analyzer,
                all_plot_requests(),
                AxisMetric::TimeMs,
                AxisMetric::Sector,
                app.time_origin(),
            ));
        }
        let result = compare_export_payload(&a, &b);
        assert_eq!(result["current"]["count"], 1);
        assert_eq!(result["current"]["read"]["bytes"], 4096);
        assert_eq!(result["current"]["read"]["valid_timing_samples"], 0);
        assert_eq!(result["current"]["read"]["unmeasured_timing_count"], 1);
        assert!(result["current"]["processes"][0]["pid"].is_null());
        assert!(result["current"]["processes"][0]["tid"].is_null());
        assert!(result["current"]["read"]["latency_ns"][0]["value"].is_null());
        assert!(issuer_label(None, None, "unknown").contains("PID unavailable"));
        assert!(issuer_label(Some(0), Some(0), "idle").contains("PID 0"));
        assert_eq!(
            b.selection
                .summary
                .as_ref()
                .unwrap()
                .files
                .values()
                .next()
                .unwrap()
                .count,
            1
        );
    }

    #[test]
    fn comparison_export_preserves_both_selections_and_refuses_source_overwrite() {
        let mut a = fixture(0, "alpha", 11, 0, 4096);
        let mut b = fixture(9_000_000_000, "beta", 22, 1, 8192);
        a.selection.summary = Some(compute_selection(
            &a.analyzer,
            all_plot_requests(),
            AxisMetric::TimeMs,
            AxisMetric::TotalLatencyMs,
            a.time_origin(),
        ));
        b.selection.summary = Some(compute_selection(
            &b.analyzer,
            SelectionRequest::Point((999, 0, 8, 0)),
            AxisMetric::TimeMs,
            AxisMetric::TotalLatencyMs,
            b.time_origin(),
        ));
        let json = compare_export_payload(&a, &b);
        assert_eq!(json["baseline"]["count"], 8);
        assert_eq!(json["current"]["count"], 0);
        assert!(json["current"]["read"]["MiB_per_s"].is_null());
        assert_eq!(json["baseline"]["processes"][0]["name"], "alpha");
        let path =
            std::env::temp_dir().join(format!("compare-source-{}.ndjson", uuid::Uuid::new_v4()));
        std::fs::write(&path, "preserve source").unwrap();
        assert!(write_compare_export(&path, &[Some(path.clone()), None], json).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "preserve source");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn empty_and_populated_comparison_plots_keep_peer_alignment() {
        let ctx = egui::Context::default();
        let mut empty = StudioApp::default();
        let mut populated = fixture(0, "alpha", 11, 0, 4096);
        empty.render_qa.output = Some(PathBuf::from("unused-geometry-capture.png"));
        populated.render_qa.output = empty.render_qa.output.clone();
        let mut qa = RenderQa::default();
        // Run more than one frame so plot axes and font metrics can settle.
        for _ in 0..3 {
            // Linked comparison views share bounds; independent ranges may
            // legitimately need different tick-label widths.
            for view in [&mut empty, &mut populated] {
                view.selection.auto_bounds = false;
                view.selection.bounds_command =
                    Some(egui_plot::PlotBounds::from_min_max([0.0, 0.0], [10.0, 1.0]));
            }
            let mut output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1440.0, 900.0),
                    )),
                    ..Default::default()
                },
                |root| {
                    egui::CentralPanel::default().show(root, |ui| {
                        ui.columns(2, |columns| {
                            compare_pane(&mut columns[0], &mut empty, "Baseline", &mut qa);
                            compare_pane(&mut columns[1], &mut populated, "Current", &mut qa);
                        });
                    });
                },
            );
            output.textures_delta.clear();
        }
        let a = qa.regions["Compare Baseline graph"].0;
        let b = qa.regions["Compare Current graph"].0;
        assert!((a.top() - b.top()).abs() < 1.0, "{a:?} versus {b:?}");
        assert!((a.width() - b.width()).abs() < 1.0, "{a:?} versus {b:?}");
        assert!(a.right() <= b.left());
    }

    #[test]
    fn narrow_summary_distributions_do_not_push_pies_outside_panel() {
        let ctx = egui::Context::default();
        let mut summary = SelectionSummary {
            access: [10, 20, 2],
            ..Default::default()
        };
        summary.read.chunks = [1, 2, 3, 4, 5];
        summary.write.chunks = [5, 4, 3, 2, 1];
        for _ in 0..3 {
            let mut output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(430.0, 1600.0),
                    )),
                    ..Default::default()
                },
                |root| {
                    egui::CentralPanel::default().show(root, |ui| {
                        let available = ui.available_width();
                        let response =
                            ui.vertical(|ui| compare_distributions(ui, &summary, &summary));
                        assert!(
                            response.response.rect.width() <= available + 1.0,
                            "pie content exceeds panel"
                        );
                    });
                },
            );
            output.textures_delta.clear();
        }
    }

    #[test]
    fn wide_comparison_keeps_summary_visible_beside_graphs() {
        let ctx = egui::Context::default();
        let mut app = fixture(0, "alpha", 11, 0, 4096);
        app.pin_comparison();
        app.render_qa.output = Some(PathBuf::from("not-written-layout-test.png"));
        for _ in 0..12 {
            let mut output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1180.0, 800.0),
                    )),
                    ..Default::default()
                },
                |root| {
                    egui::CentralPanel::default().show(root, |ui| app.compare_ui(ui));
                },
            );
            output.textures_delta.clear();
        }
        let graphs = app.render_qa.regions["Compare graphs viewport"].0;
        let (summary, clip) = app.render_qa.regions["Compare summary viewport"];
        assert!(
            graphs.right() <= summary.left(),
            "panels overlap: {graphs:?} {summary:?}"
        );
        assert!((graphs.top() - summary.top()).abs() < 1.0);
        assert!(
            summary.right() <= clip.right() + 1.0,
            "summary exceeds viewport: {summary:?} {clip:?}"
        );
        assert!(summary.bottom() <= clip.bottom() + 1.0);
        assert!(summary.contains(app.render_qa.inspector_buttons["Compare Summary"]));
    }

    #[test]
    fn file_and_process_pagination_is_scoped_to_each_session_panel() {
        let ctx = egui::Context::default();
        let mut output = ctx.run_ui(Default::default(), |root| {
            egui::CentralPanel::default().show(root, |ui| {
                for (label, expected) in [("Baseline", 1), ("Current", 0)] {
                    ui.push_id(label, |ui| {
                        let id = ui.make_persistent_id("files-page");
                        ui.ctx().data_mut(|d| d.insert_temp(id, expected));
                        assert_eq!(target_page(ui, "files-page", 50), expected);
                    });
                }
            });
        });
        output.textures_delta.clear();
    }
}
