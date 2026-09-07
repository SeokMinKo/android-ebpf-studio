// Explicit opt-in render evidence from the actual native eframe renderer.
// Physical capture requires BOTH device-start-stop and an explicit serial.
// Other scenarios never start device capture; fixtures retain their source.
#[derive(Default)]
struct RenderQa {
    waterfall: Vec<serde_json::Value>,
    filter_rebuild_ms: Vec<f64>,
    lane_page:usize,
    lane_pages:usize,
    lane_visible:Vec<String>,
    lane_page_states:Vec<serde_json::Value>,
    lane_returning:bool,
    filter_step:u32,
    filter_states:Vec<serde_json::Value>,
    activity: ActivityQa,
    latency_stable_rect: Option<egui::Rect>,
    latency_stable_frames: u32,
    latency_targets: Vec<(u32, egui::Pos2)>,
    latency_table_target: Option<egui::Pos2>,
    latency_expected: Option<LatencyRange>,
    latency_action_at: Option<Instant>,
    latency_elapsed_ms: Option<f64>,
    compare_ready_ms: Option<f64>,
    started: Option<Instant>,
    regions: BTreeMap<String, (egui::Rect, egui::Rect)>,
    session_button: Option<egui::Pos2>,
    inspector_buttons: BTreeMap<String, egui::Pos2>,
    output: Option<PathBuf>,
    frames: u32,
    requested: bool,
    plot_rect: Option<egui::Rect>,
    stable_rect: Option<egui::Rect>,
    layout_stable_since: Option<Instant>,
    point_target: Option<egui::Pos2>,
    stable_point: Option<egui::Pos2>,
    color_picker_button: Option<egui::Pos2>,
    reanalysis_restore_button: Option<egui::Pos2>,
    reanalysis_before_first: Option<u64>,
    reanalysis_window_first: Option<u64>,
    reanalysis_button: Option<egui::Pos2>,
    range_apply_button: Option<egui::Pos2>,
    range_auto_button: Option<egui::Pos2>,
    range_actions: u64,
    range_expected: Option<egui_plot::PlotBounds>,
    range_initial: Option<egui_plot::PlotBounds>,
    range_applied: Option<egui_plot::PlotBounds>,
    range_wait_frame: u32,
    zoom_button: Option<egui::Pos2>,
    back_button: Option<egui::Pos2>,
    zoom_actions: u64,
    back_actions: u64,
    input_step: u32,
    selection_before_clear: Option<usize>,
    clear_was_pending: bool,
    clear_before_bounds: Option<egui_plot::PlotBounds>,
    table_button_focused: bool,
    stop_at: Option<Instant>,
    stop_analysis_ms: Option<f64>,
    recovery_original: Option<PathBuf>,
    device_recording_at: Option<Instant>,
    device_phases: Vec<(String, f64)>,
    progress_at: Option<Instant>,
}

fn qa_record_duration() -> Duration {
    Duration::from_secs(
        std::env::var("ANDROID_EBPF_QA_RECORD_SECONDS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(6)
            .clamp(6, 1800),
    )
}

impl StudioApp {
    fn qa_input(&mut self, raw: &mut egui::RawInput) {
        if self.render_qa.output.is_none() {
            return;
        }
        // This opt-in harness owns its input stream. Desktop mouse/keyboard
        // activity must not move the graph between synthetic press and release.
        raw.events.retain(|event| {
            matches!(
                event,
                egui::Event::Screenshot { .. } | egui::Event::WindowFocused(_)
            )
        });
        let Ok(gesture) = std::env::var("ANDROID_EBPF_QA_GESTURE") else {
            return;
        };
        if gesture=="lane-pagination" || gesture=="timeline-pagination" {
            if self.render_qa.input_step>=7 || self.render_qa.frames<20 || self.render_qa.frames<self.render_qa.range_wait_frame+6 || self.footprint.pending.is_some() || self.render_qa.lane_pages==0 {return;}
            let press=self.render_qa.filter_step.is_multiple_of(2);
            if press {
                self.render_qa.lane_page_states.push(serde_json::json!({"page":self.render_qa.lane_page,"pages":self.render_qa.lane_pages,"visible":self.render_qa.lane_visible,"summary":self.selection.all_summary.as_ref().map(|s|serde_json::json!({"count":s.3.keys.len(),"p50":s.3.metric.total.percentile(50),"p95":s.3.metric.total.percentile(95)}))}));
                if self.render_qa.lane_returning || self.render_qa.lane_pages==1 {self.render_qa.input_step=7;return;}
                if self.render_qa.lane_page+1==self.render_qa.lane_pages {self.render_qa.lane_returning=true;}
            }
            let target=if gesture=="timeline-pagination" {if self.render_qa.lane_returning {"timeline-previous"}else{"timeline-next"}}else if self.render_qa.lane_returning {"previous-lanes"}else{"next-lanes"};
            if let Some((rect,_))=self.render_qa.regions.get(target) {
                let pos=rect.center();raw.events.push(egui::Event::PointerMoved(pos));
                raw.events.push(egui::Event::PointerButton{pos,button:egui::PointerButton::Primary,pressed:press,modifiers:Default::default()});
                self.render_qa.filter_step+=1;self.render_qa.range_wait_frame=self.render_qa.frames;
            }
            return;
        }
        if gesture=="process-filter" || gesture=="pid-filter" {
            let pid=gesture=="pid-filter";
            if self.render_qa.frames<20 || self.render_qa.frames<self.render_qa.range_wait_frame+6 {return;}
            let step=self.render_qa.filter_step;
            let target=match step {0|1=>Some("analysis-filters"),2|3=>Some(if pid {"pid-filter"}else{"process-filter"}),8|9=>Some("clear-filters"),_=>None};
            if let Some(target)=target {
                if let Some((rect,_))=self.render_qa.regions.get(target) {
                    let pos=rect.center();raw.events.push(egui::Event::PointerMoved(pos));
                    raw.events.push(egui::Event::PointerButton{pos,button:egui::PointerButton::Primary,pressed:step.is_multiple_of(2),modifiers:Default::default()});
                }else{return;}
            }else if step==4 || step==6 {
                raw.events.push(egui::Event::Key{key:egui::Key::A,physical_key:None,pressed:true,repeat:false,modifiers:egui::Modifiers{ctrl:true,command:true,..Default::default()}});
                raw.events.push(egui::Event::Text(if pid {if step==4 {std::env::var("ANDROID_EBPF_QA_PID").unwrap_or("1".into())}else{"2147483647".into()}}else if step==4 {std::env::var("ANDROID_EBPF_QA_PROCESS").unwrap_or("F2FS".into())}else{"__no_such_process__".into()}));
            }else if [5,7,10].contains(&step) {
                if self.y_axis==AxisMetric::SchedulerIoWait {
                    let Some(s)=&self.scheduler.view else{return;};
                    if self.scheduler.pending.is_some() || self.scheduler.signature.as_ref().is_none_or(|(g,q)|*g!=self.analysis_generation||q!=&self.query){return;}
                    let path=self.render_qa.output.as_ref().unwrap().with_extension(format!("filter-{step}.csv"));
                    let result=write_scheduler_csv(&path,s,false).map_err(|e|e.to_string());
                    self.render_qa.filter_states.push(serde_json::json!({"step":step,"query":self.query,"scheduler_count":s.rows.len(),"p50":s.distribution.percentile(50),"csv":path,"export":result}));
                    if step==10 {self.render_qa.input_step=7;self.render_qa.filter_step=11;return;}
                    self.render_qa.filter_step+=1;self.render_qa.range_wait_frame=self.render_qa.frames;return;
                }
                let Some((g,x,y,s))=&self.selection.all_summary else{return;};
                if *g!=self.analysis_generation || *x!=self.x_axis || *y!=self.y_axis || self.selection.all_pending.is_some() || self.footprint.pending.is_some(){return;}
                let path=self.render_qa.output.as_ref().unwrap().with_extension(format!("filter-{step}.csv"));
                let result=write_graph_summary_csv(&path,s).map_err(|e|e.to_string());
                let io_path=self.render_qa.output.as_ref().unwrap().with_extension(format!("filter-{step}.io.csv"));
                let io_result=session::export_completed_io_csv(&io_path,self.analysis()).map_err(|e|e.to_string());
                self.render_qa.filter_states.push(serde_json::json!({"step":step,"query":self.query,"filtered":self.analysis().completed_ios().len(),"summary":s.keys.len(),"lane_unique":self.footprint.view.as_ref().map(|v|v.unique),"host_bw":s.host_bw,"csv":path,"export":result,"io_csv":io_path,"io_export":io_result}));
                if step==10 {self.render_qa.input_step=7;self.render_qa.filter_step=11;return;}
            }else {return;}
            self.render_qa.filter_step+=1;self.render_qa.range_wait_frame=self.render_qa.frames;
            return;
        }
        if gesture.starts_with("activity-") {
            self.activity_qa_input(raw, &gesture);
            return;
        }
        if gesture.starts_with("latency-") {
            self.latency_qa_input(raw, &gesture);
            return;
        }
        if gesture == "stream-replay" || gesture.starts_with("coverage-") {
            return;
        }
        if gesture == "device-start-stop" {
            let Ok(serial) = std::env::var("ANDROID_EBPF_QA_DEVICE_SERIAL") else {
                return;
            };
            self.qa_capture_input(raw, &serial);
            return;
        }
        if matches!(
            gesture.as_str(),
            "recover-local" | "recover-phone" | "export-raw"
        ) {
            let recovery = gesture != "export-raw";
            if gesture == "recover-phone" {
                let owner_serial = self
                    .render_qa
                    .recovery_original
                    .as_deref()
                    .and_then(crate::perfetto_session::recovery_manifest)
                    .and_then(|p| std::fs::read(p).ok())
                    .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                    .and_then(|v| v.get("serial").and_then(|s| s.as_str()).map(str::to_owned));
                if owner_serial.is_none()
                    || owner_serial != std::env::var("ANDROID_EBPF_QA_DEVICE_SERIAL").ok()
                {
                    return;
                }
            }
            if self.render_qa.frames < 24
                || self.render_qa.frames < self.render_qa.range_wait_frame + 4
            {
                return;
            }
            let step = self.render_qa.input_step;
            if recovery && step == 2 {
                if self.phase == CapturePhase::Complete
                    && self.session_path != self.render_qa.recovery_original
                {
                    self.render_qa.input_step = 7;
                }
                return;
            }
            if gesture == "export-raw" && step == 4 {
                if !self.raw_export_pending
                    && self.status.starts_with("Perfetto raw trace exported")
                {
                    self.render_qa.input_step = 7;
                }
                return;
            }
            let pos = if recovery {
                self.render_qa
                    .inspector_buttons
                    .get(if gesture == "recover-phone" {
                        "Recover from original phone"
                    } else {
                        "Reanalyze saved raw trace"
                    })
                    .copied()
            } else if step < 2 {
                self.render_qa.session_button
            } else {
                self.render_qa
                    .inspector_buttons
                    .get("Export Perfetto raw trace")
                    .copied()
            };
            if step < if recovery { 2 } else { 4 }
                && let Some(pos) = pos
            {
                raw.events.push(egui::Event::PointerMoved(pos));
                raw.events.push(egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: step.is_multiple_of(2),
                    modifiers: Default::default(),
                });
                self.render_qa.input_step += 1;
                self.render_qa.range_wait_frame = self.render_qa.frames;
            }
            return;
        }
        if gesture.starts_with("compare-") {
            self.qa_compare_input(raw, &gesture);
            return;
        }
        if gesture.starts_with("navigate-") {
            let label = match gesture.as_str() {
                "navigate-slowest" => "Explain this I/O",
                "navigate-interval" => "Explore interval",
                "navigate-process" => "Explore process",
                "navigate-unresolved" => "Explore unresolved",
                _ => "Keep baseline",
            };
            let step = self.render_qa.input_step;
            if self.render_qa.frames < 24
                || (step > 0 && self.render_qa.frames < self.render_qa.range_wait_frame + 4)
            {
                return;
            }
            if step == 3 {
                let done = match gesture.as_str() {
                    "navigate-slowest" => {
                        self.page == Page::Investigate && self.selected_pipeline_request.is_some()
                    }
                    "navigate-baseline" => self.comparison.is_some(),
                    _ => self.page == Page::Explore && self.query.active(),
                };
                if done {
                    self.render_qa.input_step = 7;
                }
                return;
            }
            if step < 3
                && let Some(&pos) = self.render_qa.inspector_buttons.get(label)
            {
                raw.events.push(egui::Event::PointerMoved(pos));
                if step > 0 {
                    raw.events.push(egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed: step == 1,
                        modifiers: Default::default(),
                    });
                }
                self.render_qa.range_wait_frame = self.render_qa.frames;
                self.render_qa.input_step += 1;
            }
            return;
        }
        if gesture == "table-keyboard" {
            raw.focused = true;
            raw.events.push(egui::Event::WindowFocused(true));
            if self.render_qa.frames < 32 { return; }
            if self.render_qa.input_step == 0 && !self.render_qa.table_button_focused {
                return;
            }
            if self.render_qa.input_step < 2 {
                raw.events.push(egui::Event::Key {
                    key: egui::Key::Enter,
                    physical_key: None,
                    pressed: self.render_qa.input_step == 0,
                    repeat: false,
                    modifiers: Default::default(),
                });
                self.render_qa.input_step += 1;
            } else if self.page == Page::Investigate {
                self.render_qa.input_step = 7;
            }
            return;
        }
        if gesture == "reanalysis" {
            if self.render_qa.frames < 18 {
                return;
            }
            let mode = std::env::var("ANDROID_EBPF_QA_REANALYSIS").unwrap_or_default();
            let step = self.render_qa.input_step;
            if step == 0 {
                self.render_qa.reanalysis_before_first = self
                    .analyzer
                    .completed_ios()
                    .first()
                    .map(|io| io.issue.request_id);
                self.reanalysis.draft = match mode.as_str() {
                    "empty" => ["4000000".into(), "4000001".into()],
                    "oversize" => ["0".into(), "3000000".into()],
                    "archival" => ["0".into(), "3000".into()],
                    _ => ["1000".into(), "2000".into()],
                };
            }
            if step == 2 {
                if self.reanalysis.completed_actions == 0 {
                    return;
                }
                self.render_qa.reanalysis_window_first = self
                    .analyzer
                    .completed_ios()
                    .first()
                    .map(|io| io.issue.request_id);
                if mode != "restore" {
                    self.render_qa.input_step = 7;
                    return;
                }
            }
            if step == 4 {
                if self.reanalysis.completed_actions >= 2 {
                    self.render_qa.input_step = 7;
                }
                return;
            }
            let pos = match step {
                0 | 1 => self.render_qa.reanalysis_button,
                2 | 3 => self.render_qa.reanalysis_restore_button,
                _ => None,
            };
            if let Some(pos) = pos {
                raw.events.push(egui::Event::PointerMoved(pos));
                raw.events.push(egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: step.is_multiple_of(2),
                    modifiers: Default::default(),
                });
                self.render_qa.input_step += 1;
            }
            return;
        }
        if gesture == "range" {
            if self.render_qa.frames < 24 {
                return;
            }
            let step = self.render_qa.input_step;
            if step == 0 {
                let Some(current) = self.selection.current_bounds else {
                    return;
                };
                self.render_qa.range_initial = Some(current);
                let (mut min, mut max) = (current.min(), current.max());
                for axis in 0..2 {
                    let pad = (max[axis] - min[axis]) * 0.2;
                    min[axis] += pad;
                    max[axis] -= pad;
                }
                let bounds = egui_plot::PlotBounds::from_min_max(min, max);
                self.render_qa.range_expected = Some(bounds);
                self.selection.axis_range.read_view(bounds);
                if std::env::var("ANDROID_EBPF_QA_RANGE").as_deref() == Ok("invalid") {
                    self.selection.axis_range.values[0][0] = "NaN".into();
                }
            }
            if step == 2 {
                if self.render_qa.frames < self.render_qa.range_wait_frame + 5 {
                    return;
                }
                self.render_qa.range_applied = self.selection.current_bounds;
                if matches!(
                    std::env::var("ANDROID_EBPF_QA_RANGE").as_deref(),
                    Ok("manual") | Ok("invalid")
                ) {
                    self.render_qa.input_step = 7;
                    return;
                }
            }
            if step == 4 {
                if self.render_qa.frames >= self.render_qa.range_wait_frame + 5 {
                    self.render_qa.input_step = 7;
                }
                return;
            }
            let pos = match step {
                0 | 1 => self.render_qa.range_apply_button,
                2 | 3 => {
                    if std::env::var("ANDROID_EBPF_QA_RANGE").as_deref() == Ok("auto") {
                        self.render_qa.range_auto_button
                    } else {
                        self.render_qa.back_button
                    }
                }
                _ => None,
            };
            if let Some(pos) = pos {
                raw.events.push(egui::Event::PointerMoved(pos));
                raw.events.push(egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: step.is_multiple_of(2),
                    modifiers: Default::default(),
                });
                self.render_qa.input_step += 1;
                self.render_qa.range_wait_frame = self.render_qa.frames;
            }
            return;
        }
        if gesture == "color-picker" {
            if self.render_qa.frames >= 12
                && self.render_qa.input_step < 2
                && let Some(pos) = self.render_qa.color_picker_button
            {
                raw.events.push(egui::Event::PointerMoved(pos));
                raw.events.push(egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: self.render_qa.input_step == 0,
                    modifiers: Default::default(),
                });
                self.render_qa.input_step += 1;
            } else if self.render_qa.input_step == 2 {
                self.render_qa.input_step = 7;
            }
            return;
        }
        let Some(rect) = self.render_qa.plot_rect else {
            return;
        };
        if gesture=="point" && self.render_qa.input_step==0 && self.render_qa.point_target.is_none_or(|p|!rect.contains(p)) {
            self.render_qa.stable_rect=None;self.render_qa.stable_point=None;self.render_qa.layout_stable_since=None;return;
        }
        if self.render_qa.input_step == 0 {
            if self.render_qa.stable_rect != Some(rect) || gesture=="point" && self.render_qa.stable_point!=self.render_qa.point_target {
                self.render_qa.stable_rect = Some(rect);
                self.render_qa.stable_point = self.render_qa.point_target;
                self.render_qa.layout_stable_since = Some(Instant::now());
            }
            if self
                .render_qa
                .layout_stable_since
                .is_none_or(|time| time.elapsed() < Duration::from_millis(250))
            {
                return;
            }
        }
        let point = self.render_qa.stable_point.or(self.render_qa.point_target).unwrap_or(rect.center());
        let (start, end) = if gesture == "point" {
            (point, point)
        } else if gesture == "window-area" {
            (
                rect.min + egui::vec2(12.0, 12.0),
                egui::pos2(rect.center().x, rect.max.y - 12.0),
            )
        } else {
            (
                rect.min + egui::vec2(12.0, 12.0),
                rect.max - egui::vec2(12.0, 12.0),
            )
        };
        if self.render_qa.frames < 12 {
            return;
        }
        if self.render_qa.input_step == 3 && self.selection.summary.is_none() && gesture != "selection-cancel-pending" && !(self.y_axis==AxisMetric::SchedulerIoWait&&self.scheduler.selected.is_some()) {
            return;
        }
        if matches!(gesture.as_str(), "selection-clear" | "selection-cancel-pending") && self.render_qa.input_step >= 3 {
            let step = self.render_qa.input_step;
            if step >= 7 { return; }
            if step == 3 {
                if !self.selection.has_selection() { return; }
                self.render_qa.selection_before_clear = self.selection.summary.as_ref().map(|s| s.keys.len());
                self.render_qa.clear_was_pending = self.selection.pending.is_some();
                self.render_qa.clear_before_bounds = self.selection.current_bounds;
            }
            if step == 6 {
                if !self.selection.has_selection() { self.render_qa.input_step = 7; }
                return;
            }
            if let Some((rect, _)) = self.render_qa.regions.get("clear-selection") {
                let pos = rect.center();
                raw.events.push(egui::Event::PointerMoved(pos));
                if step > 3 { raw.events.push(egui::Event::PointerButton {pos, button: egui::PointerButton::Primary, pressed: step == 4, modifiers: Default::default()}); }
                self.render_qa.input_step += 1;
            }
            return;
        }
        if gesture.starts_with("inspector-") && self.render_qa.input_step >= 3 {
            let label = if gesture == "inspector-files" {
                "Files"
            } else {
                "Processes"
            };
            let step = self.render_qa.input_step;
            if step == 6 {
                if (label == "Files" && self.selection.inspector_tab == InspectorTab::Files)
                    || (label == "Processes"
                        && self.selection.inspector_tab == InspectorTab::Processes)
                {
                    self.render_qa.input_step = 7;
                }
                return;
            }
            if step >= 4 && self.render_qa.frames < self.render_qa.range_wait_frame + 6 {
                return;
            }
            if step < 6
                && let Some(&pos) = self.render_qa.inspector_buttons.get(label)
            {
                raw.events.push(egui::Event::PointerMoved(pos));
                if step > 3 {
                    raw.events.push(egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed: step == 4,
                        modifiers: Default::default(),
                    });
                }
                self.render_qa.range_wait_frame = self.render_qa.frames;
                self.render_qa.input_step += 1;
            }
            return;
        }
        if self.render_qa.input_step == 3 && gesture != "zoom-back" {
            self.render_qa.input_step = 7;
            return;
        }
        let action = match self.render_qa.input_step {
            0 => Some((start, Some(true))),
            1 => Some((end, None)),
            2 => Some((end, Some(false))),
            3 => self.render_qa.zoom_button.map(|p| (p, Some(true))),
            4 => self.render_qa.zoom_button.map(|p| (p, Some(false))),
            5 if self.render_qa.zoom_actions > 0 => {
                self.render_qa.back_button.map(|p| (p, Some(true)))
            }
            6 => self.render_qa.back_button.map(|p| (p, Some(false))),
            _ => None,
        };
        if let Some((pos, pressed)) = action {
            self.render_qa.input_step += 1;
            raw.events.push(egui::Event::PointerMoved(pos));
            if let Some(pressed) = pressed {
                raw.events.push(egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: Default::default(),
                });
            }
        }
    }
    fn initialize_render_qa(&mut self) {
        let Some(output) = std::env::var_os("ANDROID_EBPF_QA_OUTPUT") else {
            return;
        };
        self.render_qa.output = Some(PathBuf::from(output));
        self.render_qa.started = Some(Instant::now());
        if std::env::var("ANDROID_EBPF_QA_GESTURE").as_deref() == Ok("stream-replay")
            && let Some(path) = std::env::var_os("ANDROID_EBPF_QA_STREAM_SESSION")
        {
            // Read-only replay through the same bounded channel and UI drain as
            // capture. No writer is opened against the original session.
            let path = PathBuf::from(path);
            self.session_path = Some(path.clone());
            self.phase = CapturePhase::Analyzing;
            self.render_qa.stop_at = Some(Instant::now());
            let tx = self.tx.clone();
            std::thread::spawn(move || {
                use std::io::BufRead;
                let result = (|| -> anyhow::Result<()> {
                    tx.send(HostMessage::AnalysisStarted)
                        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                    let input = std::io::BufReader::new(std::fs::File::open(path)?);
                    for line in input.lines() {
                        let line = line?;
                        if !line.trim().is_empty() {
                            tx.send(HostMessage::Record(serde_json::from_str(&line)?))
                                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                        }
                    }
                    Ok(())
                })()
                .map_err(|e| e.to_string());
                let _ = tx.send(HostMessage::Ended(result));
            });
        }
        if let Some(path) = std::env::var_os("ANDROID_EBPF_QA_SESSION") {
            let path = PathBuf::from(path);
            match session::load_analysis(&path) {
                Ok(loaded) => self.apply_loaded_session(path, loaded),
                Err(error) => {
                    self.status = format!("QA session failed: {error}");
                    self.phase = CapturePhase::Error;
                }
            }
        }
        if let Some(path) = std::env::var_os("ANDROID_EBPF_QA_BASELINE") {
            self.start_comparison_load(PathBuf::from(path));
        }
        if matches!(
            std::env::var("ANDROID_EBPF_QA_GESTURE").as_deref(),
            Ok("recover-local" | "recover-phone")
        ) {
            self.render_qa.recovery_original = self.session_path.clone();
            self.phase = CapturePhase::Error;
            self.status = "QA interrupted-session state; original raw capture retained".into();
        }
        if std::env::var_os("ANDROID_EBPF_QA_SIMULATOR").is_some() {
            self.start_simulator();
        }
        if let Ok(scale) = std::env::var("ANDROID_EBPF_QA_SCALE")
            && let Ok(scale) = scale.parse::<f32>()
        {
            self.render_qa_scale = Some(scale);
        }
        self.theme = match std::env::var("ANDROID_EBPF_QA_THEME").as_deref() {
            Ok("light") => ThemeChoice::Light,
            Ok("contrast") => ThemeChoice::HighContrast,
            _ => ThemeChoice::Dark,
        };
        self.page = match std::env::var("ANDROID_EBPF_QA_PAGE").as_deref() {
            Ok("explore") => {
                self.explorer_preset = ExplorerPreset::Custom;
                self.x_axis = AxisMetric::TimeMs;
                self.y_axis = AxisMetric::Sector;
                Page::Explore
            }
            Ok("investigate") => Page::Investigate,
            Ok("diagnostics") => Page::Diagnostics,
            Ok("compare") => Page::Compare,
            Ok("overview") => Page::Overview,
            _ => self.page,
        };
    }

    fn apply_qa_preset(&mut self) {
        // The preset is applied after the first rendered frame. Discard that
        // frame's old-axis coordinates before a background summary becomes ready.
        self.render_qa.plot_rect=None;self.render_qa.point_target=None;
        self.render_qa.stable_rect=None;self.render_qa.stable_point=None;
        self.render_qa.layout_stable_since=None;
        if let Ok(device)=std::env::var("ANDROID_EBPF_QA_DEVICE_FILTER") {self.query.device=device;self.invalidate_query();}
        if let Ok(mode) = std::env::var("ANDROID_EBPF_QA_FOOTPRINT") {
            self.footprint.mode = match mode.as_str() {
                "file" => FootprintMode::FilePath,
                "process" => FootprintMode::Process,
                "origin" => FootprintMode::FileProcess,
                _ => FootprintMode::Combined,
            };
            self.footprint.fit = true;
        }
        if std::env::var("ANDROID_EBPF_QA_AXES").as_deref() == Ok("address-chunk") {
            self.x_axis = AxisMetric::Sector;
            self.y_axis = AxisMetric::ChunkKiB;
            self.compare_explore.preset = ExplorerPreset::Custom;
            self.compare_explore.axes = [self.x_axis, self.y_axis];
            self.compare_explore.needs_apply = true;
            self.compare_explore.fit = true;
            self.render_qa.compare_ready_ms = None;
        }
        if let Ok(filter) = std::env::var("ANDROID_EBPF_QA_FILTER") {
            match filter.as_str() {
                "read" => self.query.operation = Some(IoOperation::Read),
                "write" => self.query.operation = Some(IoOperation::Write),
                "file" => self.query.file = "final-A.bin".into(),
                "unresolved" => self.query.confidence = Some(PathConfidence::Unresolved),
                _ => {}
            }
            self.invalidate_query();
        }
        if let Ok(mode) = std::env::var("ANDROID_EBPF_QA_PLOT_STYLE") {
            self.group_by = GroupBy::Direction;
            if mode != "auto" {
                self.plot_style.point_diameter = 16.0;
                self.plot_style
                    .set_color(GroupBy::Direction, "Read", [210, 40, 170]);
                self.plot_style
                    .set_color(GroupBy::Direction, "Write", [240, 100, 20]);
            }
            if mode == "write-only" {
                self.query.operation = Some(IoOperation::Write);
                self.invalidate_query();
            }
            if mode == "file" {
                self.group_by = GroupBy::File;
            }
        }
        if let Ok(preset) = std::env::var("ANDROID_EBPF_QA_PRESET")
            && let Ok(index) = preset.parse::<usize>()
            && let Some(value) = ExplorerPreset::ALL.get(index)
            && let Some((x, y, group)) = value.query()
        {
            self.explorer_preset = *value;
            self.x_axis = x;
            self.y_axis = y;
            self.group_by = group;
            self.compare_explore.preset = *value;
            self.compare_explore.axes = [x, y];
            self.compare_explore.category = group;
            self.compare_explore.needs_apply = true;
        }
        if let Ok(style)=std::env::var("ANDROID_EBPF_QA_GEOMETRY") {self.custom_geometry=match style.as_str(){"line"=>CustomGeometry::Line,"bar"=>CustomGeometry::Bar,_=>CustomGeometry::Scatter};}
        if let Ok(axis) = std::env::var("ANDROID_EBPF_QA_Y_AXIS")
            && let Ok(index) = axis.parse::<usize>()
            && let Some(axis) = AxisMetric::ALL.get(index) {
            self.x_axis = AxisMetric::TimeMs;
            self.y_axis = *axis;
            self.explorer_preset = ExplorerPreset::Custom;
        }
        if let Ok(axis)=std::env::var("ANDROID_EBPF_QA_X_AXIS") && let Ok(index)=axis.parse::<usize>() && let Some(axis)=AxisMetric::ALL.get(index) {self.x_axis= *axis;self.explorer_preset=ExplorerPreset::Custom;}
    }
    fn render_qa_tick(&mut self, ctx: &egui::Context) {
        let Some(path) = self.render_qa.output.clone() else {
            return;
        };
        self.render_qa.frames += 1;
        if std::env::var("ANDROID_EBPF_QA_GESTURE").as_deref() == Ok("device-start-stop") {
            let label = self.phase.label().to_owned();
            if self
                .render_qa
                .device_phases
                .last()
                .is_none_or(|(p, _)| *p != label)
            {
                self.render_qa.device_phases.push((
                    label,
                    self.render_qa.started.unwrap().elapsed().as_secs_f64() * 1000.0,
                ));
                self.render_qa.progress_at = None;
            }
            if self
                .render_qa
                .progress_at
                .is_none_or(|t| t.elapsed() >= Duration::from_secs(2))
            {
                let _=std::fs::write(path.with_extension("progress.json"),serde_json::to_vec_pretty(&serde_json::json!({"phase":self.phase.label(),"phases":self.render_qa.device_phases,"session":self.session_path,"status":self.status,"frames":self.render_qa.frames,"ui_performance":self.performance.snapshot(),"elapsed_ms":self.render_qa.started.unwrap().elapsed().as_secs_f64()*1000.0})).unwrap());
                self.render_qa.progress_at = Some(Instant::now());
            }
            if self.phase == CapturePhase::Recording && self.render_qa.device_recording_at.is_none()
            {
                self.render_qa.device_recording_at = Some(Instant::now());
            }
        }
        if self.render_qa.frames == 1 {
            self.apply_qa_preset();
        }
        if std::env::var("ANDROID_EBPF_QA_GESTURE").as_deref() == Ok("stream-replay")
            && matches!(self.phase, CapturePhase::Complete | CapturePhase::Error)
        {
            if self.render_qa.stop_analysis_ms.is_none() {
                self.render_qa.stop_analysis_ms = self
                    .render_qa
                    .stop_at
                    .map(|t| t.elapsed().as_secs_f64() * 1000.0);
            }
            self.render_qa.input_step = 7;
        }
        if let Some(scale) = self.render_qa_scale.take() {
            ctx.set_pixels_per_point(scale);
        }
        if std::env::var_os("ANDROID_EBPF_QA_SMALL").is_some() && self.render_qa.frames == 2 {
            ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(800.0, 600.0)));
        }
        if std::env::var_os("ANDROID_EBPF_QA_SIMULATOR").is_some() {
            if self.phase == CapturePhase::Recording
                && self
                    .started_at
                    .is_some_and(|t| t.elapsed() >= Duration::from_secs(3))
            {
                self.render_qa.stop_at = Some(Instant::now());
                self.stop();
            }
            if self.phase == CapturePhase::Complete && self.render_qa.stop_analysis_ms.is_none() {
                self.render_qa.stop_analysis_ms = self
                    .render_qa
                    .stop_at
                    .map(|t| t.elapsed().as_secs_f64() * 1000.0);
            }
        }
        let screenshot = ctx.input(|i| {
            i.events.iter().find_map(|event| {
                if let egui::Event::Screenshot { image, .. } = event {
                    Some(image.clone())
                } else {
                    None
                }
            })
        });
        let timed_out = self.render_qa.started.is_some_and(|s| {
            s.elapsed()
                > Duration::from_secs(
                    if std::env::var("ANDROID_EBPF_QA_GESTURE").as_deref()
                        == Ok("device-start-stop")
                    {
                        qa_record_duration().as_secs() + 49
                    } else if std::env::var("ANDROID_EBPF_QA_GESTURE").as_deref()
                        == Ok("stream-replay")
                    {
                        120
                    } else if std::env::var("ANDROID_EBPF_QA_GESTURE").as_deref()
                        == Ok("timeline-pagination")
                    {
                        180
                    } else if std::env::var("ANDROID_EBPF_QA_GESTURE").as_deref()
                        == Ok("lane-pagination")
                    {
                        45
                    } else {
                        std::env::var("ANDROID_EBPF_QA_TIMEOUT_SECONDS")
                            .ok()
                            .and_then(|value| value.parse::<u64>().ok())
                            .unwrap_or(8)
                            .clamp(8, 120)
                    },
                )
        }) && self.render_qa.input_step < 7
            && std::env::var_os("ANDROID_EBPF_QA_GESTURE").is_some();
        if let Some(screenshot) = screenshot {
            let pixels: Vec<u8> = screenshot
                .pixels
                .iter()
                .flat_map(|pixel| pixel.to_array())
                .collect();
            let result = image::save_buffer(
                &path,
                &pixels,
                screenshot.width() as u32,
                screenshot.height() as u32,
                image::ColorType::Rgba8,
            );
            let mut report = serde_json::json!({ "capture": path, "result": result.as_ref().map(|_| "saved").map_err(|e| e.to_string()), "phase": self.phase.label(), "page": format!("{:?}", self.page), "theme": format!("{:?}",self.theme), "completed_requests": self.analysis().completed_ios().len(), "received_events": self.received_events, "rejected": self.rejected_records, "frames": self.render_qa.frames, "reanalysis_before_first":self.render_qa.reanalysis_before_first,"reanalysis_window_first":self.render_qa.reanalysis_window_first,"source_completed_ios":self.reanalysis.source_count,"reanalysis_window_ns":self.reanalysis.window,"reanalysis_ms":self.reanalysis.elapsed_ms,"reanalysis_error":self.reanalysis.error,"reanalysis_actions":self.reanalysis.completed_actions,"file_evidence_count":self.file_evidence_positions.as_ref().map(|v|v.len()),"file_evidence_total":self.analysis().file_ios().len(),"filtered_read_ios":self.analysis().completed_ios().iter().filter(|io|io.issue.operation==IoOperation::Read).count(),"filtered_write_ios":self.analysis().completed_ios().iter().filter(|io|io.issue.operation==IoOperation::Write).count(),"explorer_available":self.explorer_view.as_ref().map(|v|v.available),"range_draft":self.selection.axis_range.values,"range_actions":self.render_qa.range_actions,"range_error":self.selection.axis_range.error,"range_initial":self.render_qa.range_initial.map(|b|[b.min(),b.max()]),"range_expected":self.render_qa.range_expected.map(|b|[b.min(),b.max()]),"range_applied":self.render_qa.range_applied.map(|b|[b.min(),b.max()]),"plot_bounds":self.selection.current_bounds.map(|b|[b.min(),b.max()]),"point_diameter":self.plot_style.point_diameter,"color_category":format!("{:?}",self.group_by),"rendered_colors":self.explorer_view.as_ref().map(|view|view.groups.iter().map(|(name,_)|(name,self.plot_style.color(self.group_by,name).to_array())).collect::<BTreeMap<_,_>>()), "stop_analysis_ms":self.render_qa.stop_analysis_ms,"session_path":self.session_path,"selected_files":self.selection.summary.as_ref().map(|s|s.files.len()),"selected_processes":self.selection.summary.as_ref().map(|s|s.processes.len()),"selection_count": self.selection.summary.as_ref().map(|s|s.keys.len()), "selection_ms": self.selection.summary.as_ref().map(|s|s.elapsed.as_secs_f64()*1000.0), "zoom_history_depth": self.selection.zoom_history.len(), "zoom_actions": self.render_qa.zoom_actions, "back_actions": self.render_qa.back_actions, "ui_performance": self.performance.snapshot() });
            report["rendered_waterfall"] = serde_json::json!(self.render_qa.waterfall);
            if let Some(text)=&self.raw_log.text {let raw=path.with_extension("raw-log.txt");let _=std::fs::write(&raw,text);report["raw_log"]=serde_json::json!({"path":raw,"loaded":true,"characters":text.len()});}
            report["overall"]=self.explorer_view.as_ref().map_or(serde_json::Value::Null,|v|serde_json::json!({"points":v.overall.rows.len(),"qd_measured":v.overall.rows.iter().filter(|r|r.2.is_some()).count()}));
            report["custom_axes"]=self.explorer_view.as_ref().map_or(serde_json::Value::Null,|v|serde_json::json!({"x":v.x_categories.labels,"y":v.y_categories.labels,"geometry":format!("{:?}",self.custom_geometry)}));
            report["filter_rebuild_ms"]=serde_json::json!(self.render_qa.filter_rebuild_ms);
            report["comparison_explore"] = self.compare_qa_report();
            report["filter_states"]=serde_json::json!(self.render_qa.filter_states);
            report["lane_page_states"]=serde_json::json!(self.render_qa.lane_page_states);
            report["timeline"]=self.selection.summary.as_ref().or_else(||self.selection.all_summary.as_ref().map(|v|&v.3)).and_then(|s|s.timeline.as_ref()).map_or(serde_json::Value::Null,|v|serde_json::json!(v));
            report["footprint"] = self.footprint.view.as_ref().map_or(serde_json::Value::Null, |v| serde_json::json!({"mode":v.mode.label(),"unique":v.unique,"memberships":v.memberships,"groups":v.lanes.iter().map(|(k,p)|(k,p.len())).collect::<BTreeMap<_,_>>() }));
            if self.connected_footprint() && let Some(view)=&self.footprint.view {
                report["connected_footprint"]=serde_json::json!({"completion_selected_rectangles":true,"points":view.lanes.iter().flat_map(|(lane,points)|points.iter().map(move|p|serde_json::json!({"lane":lane,"key":p.point.request,"issue_ms":p.issue_ms,"completion_ms":p.point.coordinates[0],"sector":p.point.coordinates[1],"end_sector":p.end_sector,"operation":p.operation}))).collect::<Vec<_>>()});
            }
            report["graph_summary"] = self.selection.summary.as_ref()
                .or_else(||self.selection.all_summary.as_ref().map(|v|&v.3))
                .map_or(serde_json::Value::Null, |s| serde_json::json!({
                    "metric":s.metric_axis.map(AxisMetric::label),
                    "samples":s.metric.total.values.len(),"missing":s.metric.total.missing,
                    "p50":s.metric.total.percentile(50),"p95":s.metric.total.percentile(95),
                    "histogram":s.metric.total.histogram(16),"cdf":s.metric.total.cdf_points(512),"address_counts":s.address_counts,
                    "cohort_count":s.keys.len(),"selected":self.selection.summary.is_some(),"host_bw":s.host_bw,"categories":s.categories,"window_series":s.window_series
                }));
            if let Some(s)=self.selection.summary.as_ref().or_else(||self.selection.all_summary.as_ref().map(|v|&v.3)) {
                let csv=path.with_extension("summary.csv");
                report["graph_summary_export"]=serde_json::json!({"path":csv,"result":write_graph_summary_csv(&csv,s).map_err(|e|e.to_string())});
                let io_csv=path.with_extension("io.csv");
                let cohort=self.analysis().select_completed(|io|s.keys.contains(&selection_key(io)));
                report["graph_io_export"]=serde_json::json!({"path":io_csv,"result":session::export_completed_io_csv(&io_csv,&cohort).map_err(|e|e.to_string())});
            }
            report["explorer_axes"] = serde_json::json!([self.x_axis.label(), self.y_axis.label()]);
            if std::env::var_os("ANDROID_EBPF_QA_DEPTH").is_some() {
                report["depth_selected_keys"] =
                    serde_json::json!(self.selection.summary.as_ref().map(|s| &s.keys));
                report["queue_depth_samples"] = serde_json::json!(self.analysis().completed_ios().iter().map(|io| serde_json::json!({"key":selection_key(io),"at_issue":io.queue_depth_at_issue,"after_completion":io.queue_depth_after})).collect::<Vec<_>>());
                report["explorer_coordinates"] =
                    serde_json::json!(self.explorer_view.as_ref().map(|v| {
                        v.groups
                            .iter()
                            .flat_map(|(_, points)| points.iter().map(|p| p.coordinates))
                            .collect::<Vec<_>>()
                    }));
            }
            report["activity"] = serde_json::json!(self.render_qa.activity);
            if self.render_qa.activity.expected_second.is_some() {
                report["activity_selected_keys"] =
                    serde_json::json!(self.selection.summary.as_ref().map(|s| &s.keys));
            }
            report["session_file_path_coverage"] = serde_json::json!(self.file_path_coverage);
            report["latency_expected"] = serde_json::json!(self.render_qa.latency_expected);
            report["latency_drilldown_ms"] = serde_json::json!(self.render_qa.latency_elapsed_ms);
            if self.render_qa.latency_expected.is_some() {
                report["latency_selected_keys"] =
                    serde_json::json!(self.selection.summary.as_ref().map(|s| &s.keys));
            }
            report["displayed_summary"] =
                serde_json::json!(self.summary_view.as_ref().map(|(_, _, summary)| summary));
            if self.y_axis==AxisMetric::SchedulerIoWait && let Some(s)=self.scheduler.selected.as_ref().or(self.scheduler.view.as_ref()) {
                report["scheduler"]=serde_json::json!(s);
                report["selection_count"]=serde_json::json!(self.scheduler.selected.as_ref().map(|v|v.rows.len()));
                report["graph_summary"]=serde_json::json!({"metric":"Scheduler I/O wait (us)","samples":s.rows.len(),"p50":s.distribution.percentile(50),"p95":s.distribution.percentile(95),"histogram":s.distribution.histogram(16),"selected":self.scheduler.selected.is_some()});
                let csv=path.with_extension("summary.csv");
                report["graph_summary_export"]=serde_json::json!({"path":csv,"result":write_scheduler_csv(&csv,s,true).map_err(|e|e.to_string())});
                let csv=path.with_extension("scheduler.csv");
                report["scheduler_export"]=serde_json::json!({"path":csv,"result":write_scheduler_csv(&csv,s,false).map_err(|e|e.to_string())});
                report["graph_io_export"]=serde_json::Value::Null;
            }
            report["trend_request_count"] = serde_json::json!(
                self.trend_view
                    .as_ref()
                    .map(|(_, trend)| trend.coverage.iter().sum::<u64>())
            );
            report["recovery_original"] = serde_json::json!(self.render_qa.recovery_original);
            report["device_phases"] = serde_json::json!(self.render_qa.device_phases);
            report["preflight"] = serde_json::json!(self.preflight);
            report["source_info"] = serde_json::json!(self.source_info);
            report["loss_status"] = serde_json::json!(self.loss_status);
            report["status"] = serde_json::json!(self.status);
            report["qa_timed_out"] = serde_json::json!(timed_out);
            report["selection_before_clear"] = serde_json::json!(self.render_qa.selection_before_clear);
            report["clear_was_pending"] = serde_json::json!(self.render_qa.clear_was_pending);
            report["selection_pending"] = serde_json::json!(self.selection.pending.is_some());
            report["clear_before_bounds"] = serde_json::json!(self.render_qa.clear_before_bounds.map(|b| [b.min(), b.max()]));
            report["qa_timeout_override_seconds"] = serde_json::json!(std::env::var("ANDROID_EBPF_QA_TIMEOUT_SECONDS").ok());
            report["active_filter"] = serde_json::json!(self.query);
            report["baseline_count"] =
                serde_json::json!(self.comparison.as_ref().map(|b| b.summary.completed_ios));
            report["opened_io"] = serde_json::json!(self.selected_pipeline_request);
            report["inspector_tab"] =
                serde_json::json!(format!("{:?}", self.selection.inspector_tab));
            report["viewport"] = serde_json::json!([
                [ctx.content_rect().min.x, ctx.content_rect().min.y],
                [ctx.content_rect().max.x, ctx.content_rect().max.y]
            ]);
            report["regions"] = serde_json::json!(self.render_qa.regions.iter().map(|(name,(r,c))|(name,serde_json::json!({"rect":[[r.min.x,r.min.y],[r.max.x,r.max.y]],"clip":[[c.min.x,c.min.y],[c.max.x,c.max.y]]}))).collect::<BTreeMap<_,_>>());
            report["qa_input_step"] = serde_json::json!(self.render_qa.input_step);
            report["table_button_focused"] = serde_json::json!(self.render_qa.table_button_focused);
            let _ = std::fs::write(
                path.with_extension("json"),
                serde_json::to_vec_pretty(&report).unwrap(),
            );
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        } else if !self.render_qa.requested
            && (timed_out
                || (self.render_qa.frames >= 40
                    && self.selection.pending.is_none()
                    && self.selection.all_pending.is_none()
                    && (self.y_axis!=AxisMetric::SchedulerIoWait || (self.scheduler.pending.is_none() && self.scheduler.selected_pending.is_none()))
                    && self.footprint.pending.is_none()
                    && self.raw_log.pending.is_none()
                    && self.compare_explore.pending.is_none()
                    && self
                        .comparison
                        .as_ref()
                        .is_none_or(|b| b.viewer.selection.pending.is_none())
                    && self
                        .compare_explore
                        .current
                        .as_ref()
                        .is_none_or(|b| b.selection.pending.is_none())
                    && !self.render_qa.requested
                    && !self.is_running()
                    && (std::env::var_os("ANDROID_EBPF_QA_GESTURE").is_none()
                        || self.render_qa.input_step >= 7
                        || (std::env::var_os("ANDROID_EBPF_QA_TABLE_KEYBOARD").is_some()
                            && self.render_qa.frames >= 160))))
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(Default::default()));
            self.render_qa.requested = true;
        }
        ctx.request_repaint_after(Duration::from_millis(50));
    }
}

impl StudioApp {
    fn qa_capture_input(&mut self, raw: &mut egui::RawInput, serial: &str) {
            if self.render_qa.frames < 24
                || self.render_qa.frames < self.render_qa.range_wait_frame + 4
            {
                return;
            }
            let step = self.render_qa.input_step;
            if self.phase == CapturePhase::Error {
                self.render_qa.input_step = 7;
                return;
            }
            if step >= 4 {
                if self.phase == CapturePhase::Complete {
                    self.render_qa.stop_analysis_ms = self
                        .render_qa
                        .stop_at
                        .map(|t| t.elapsed().as_secs_f64() * 1000.0);
                    self.render_qa.input_step = 7;
                }
                return;
            }
            if step < 2 && self.selected_serial.as_deref() != Some(serial) {
                return;
            }
            if step == 2
                && !(self.phase == CapturePhase::Recording
                    && self
                        .render_qa
                        .device_recording_at
                        .is_some_and(|t| t.elapsed() >= qa_record_duration()))
            {
                return;
            }
            if let Some((rect, _)) = self.render_qa.regions.get("capture-action") {
                let pos = rect.center();
                raw.events.push(egui::Event::PointerMoved(pos));
                // Press and release in one input frame: a busy renderer must not
                // turn an automated click into egui's long-press gesture.
                for pressed in [true, false] {
                    raw.events.push(egui::Event::PointerButton {
                        pos, button:egui::PointerButton::Primary, pressed,
                        modifiers:Default::default(),
                    });
                }
                if step == 2 { self.render_qa.stop_at=Some(Instant::now()); }
                self.render_qa.input_step += 2;
                self.render_qa.range_wait_frame = self.render_qa.frames;
            }

    }
}

#[cfg(test)]
mod live_capture_qa_tests {
    use super::*;
    #[test]
    fn capture_button_click_survives_slow_frames() {
        let ctx=egui::Context::default();
        let mut app=StudioApp::default();
        app.render_qa.frames=24;
        app.render_qa.input_step=2;
        app.phase=CapturePhase::Recording;
        app.render_qa.device_recording_at=Some(Instant::now()-Duration::from_secs(3600));
        let mut clicked=false;
        for frame in 0..8 {
            let mut raw=egui::RawInput {time:Some(frame as f64 * 0.6),..Default::default()};
            app.qa_capture_input(&mut raw,"fixture");
            let mut output=ctx.run_ui(raw, |root| { egui::CentralPanel::default().show(root, |ui| {
                let response=ui.button("Stop & analyze");
                app.render_qa.regions.insert("capture-action".into(),(response.rect,response.rect));
                clicked |= response.clicked();
            }); });
            output.textures_delta.clear();
            app.render_qa.frames+=1;
        }
        assert!(clicked,"synthetic capture gesture must be a click even when each frame takes 600 ms");
    }
    #[test]
    #[ignore = "opt-in saved real trace diagnostic"]
    fn measure_live_overview_trace() {
        use std::io::BufRead;
        let path=std::env::var("ANDROID_EBPF_LIVE_PROBE").unwrap();
        let mut engine=AnalysisEngine::new();
        for line in std::io::BufReader::new(std::fs::File::open(path).unwrap()).lines() {
            if let WireRecord::Event {event,..}=serde_json::from_str(&line.unwrap()).unwrap() {engine.ingest(event);}
        }
        let count=engine.completed_ios().len();
        let mut app=StudioApp {analyzer:engine,phase:CapturePhase::Recording,..Default::default()};
        let start=Instant::now(); app.refresh_trend_view(); let enqueue_ms=start.elapsed().as_secs_f64()*1000.;
        assert!(app.trend_view.is_none());
        assert!(enqueue_ms<150.,"Overview blocks the UI for {enqueue_ms:.2} ms");
        let deadline=Instant::now()+Duration::from_secs(30);
        while app.trend_view.is_none() {
            app.refresh_trend_view();
            assert!(Instant::now()<deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(app.trend_view.as_ref().unwrap().1.coverage.iter().sum::<u64>(),count as u64);
        eprintln!("live overview: count={count} UI enqueue_ms={enqueue_ms:.2}, background result verified");
    }
}
