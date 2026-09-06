// Explicit opt-in render evidence from the actual native eframe renderer.
// Physical capture requires BOTH device-start-stop and an explicit serial.
// Other scenarios never start device capture; fixtures retain their source.
#[derive(Default)]
struct RenderQa {
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
        if gesture == "stream-replay" {
            return;
        }
        if gesture == "device-start-stop" {
            let Ok(serial) = std::env::var("ANDROID_EBPF_QA_DEVICE_SERIAL") else {
                return;
            };
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
            if step < 2 && self.selected_serial.as_deref() != Some(serial.as_str()) {
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
                raw.events.push(egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: step.is_multiple_of(2),
                    modifiers: Default::default(),
                });
                if step == 3 {
                    self.render_qa.stop_at = Some(Instant::now());
                }
                self.render_qa.input_step += 1;
                self.render_qa.range_wait_frame = self.render_qa.frames;
            }
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
            if !self.render_qa.table_button_focused {
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
        if self.render_qa.input_step == 0 {
            if self.render_qa.stable_rect != Some(rect) {
                self.render_qa.stable_rect = Some(rect);
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
        let point = self.render_qa.point_target.unwrap_or(rect.center());
        let (start, end) = if gesture == "point" {
            (point, point)
        } else {
            (
                rect.min + egui::vec2(12.0, 12.0),
                rect.max - egui::vec2(12.0, 12.0),
            )
        };
        if self.render_qa.frames < 12 {
            return;
        }
        if self.render_qa.input_step == 3 && self.selection.summary.is_none() {
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
            _ => Page::Overview,
        };
    }

    fn apply_qa_preset(&mut self) {
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
            self.x_axis = x;
            self.y_axis = y;
            self.group_by = group;
        }
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
                    } else {
                        8
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
            report["comparison_explore"] = self.compare_qa_report();
            report["displayed_summary"] =
                serde_json::json!(self.summary_view.as_ref().map(|(_, _, summary)| summary));
            report["trend_request_count"] = serde_json::json!(
                self.trend_view
                    .as_ref()
                    .map(|(_, trend)| trend.coverage.iter().sum::<u64>())
            );
            report["recovery_original"] = serde_json::json!(self.render_qa.recovery_original);
            report["device_phases"] = serde_json::json!(self.render_qa.device_phases);
            report["preflight"] = serde_json::json!(self.preflight);
            report["source_info"] = serde_json::json!(self.source_info);
            report["status"] = serde_json::json!(self.status);
            report["qa_timed_out"] = serde_json::json!(timed_out);
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
