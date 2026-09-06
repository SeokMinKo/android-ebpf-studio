#[derive(Default)]
struct ReanalysisState {
    source_start_ns: Option<u64>,
    source_end_ns: u64,
    source_count: u64,
    window: Option<(u64, u64)>,
    elapsed_ms: f64,
    draft: [String; 2],
    pending: Option<Receiver<Result<session::LoadedAnalysis, String>>>,
    cancel: Option<Arc<AtomicBool>>,
    error: Option<String>,
    completed_actions: u64,
}

fn parse_reanalysis_range(values: &[String; 2], origin: u64) -> Result<(u64, u64), String> {
    let mut times = [0u64; 2];
    for i in 0..2 {
        let value = values[i]
            .trim()
            .parse::<f64>()
            .map_err(|_| "Enter Start and End in milliseconds".to_owned())?;
        if !value.is_finite() || value < 0.0 || value * 1e6 >= (u64::MAX - origin) as f64 {
            return Err("Time must be finite, nonnegative and within the timestamp range".into());
        }
        times[i] = origin + (value * 1e6).round() as u64;
    }
    if times[0] >= times[1] {
        return Err("Start must be less than End".into());
    }
    Ok((times[0], times[1]))
}

impl StudioApp {
    fn begin_reanalysis(&mut self, window: Option<(u64, u64)>) {
        if self.is_running() || self.reanalysis.pending.is_some() {
            return;
        }
        let Some(path) = self.session_path.clone() else {
            return;
        };
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let (tx, rx) = bounded(1);
        self.reanalysis.pending = Some(rx);
        self.reanalysis.cancel = Some(cancel);
        self.reanalysis.error = None;
        self.phase = CapturePhase::Analyzing;
        self.status =
            "Reading original session in background… previous view preserved until ready".into();
        std::thread::spawn(move || {
            let _ = tx.send(
                session::load_analysis_window(&path, window, Some(&worker_cancel))
                    .map_err(|e| e.to_string()),
            );
        });
    }

    fn poll_reanalysis(&mut self) {
        let result = self
            .reanalysis
            .pending
            .as_ref()
            .and_then(|rx| match rx.try_recv() {
                Ok(result) => Some(result),
                Err(crossbeam_channel::TryRecvError::Disconnected) => Some(Err(
                    "Reanalysis worker stopped; previous view preserved".into(),
                )),
                Err(crossbeam_channel::TryRecvError::Empty) => None,
            });
        let Some(result) = result else {
            return;
        };
        self.reanalysis.completed_actions += 1;
        self.reanalysis.pending = None;
        let cancelled = self
            .reanalysis
            .cancel
            .take()
            .is_some_and(|v| v.load(Ordering::Relaxed));
        if cancelled {
            self.phase = CapturePhase::Complete;
            self.status = "Reanalysis cancelled · previous view preserved".into();
            return;
        }
        match result {
            Ok(loaded) => {
                let mut query = self.query.clone();
                query.request_keys = None;
                query.start_ms = 0.0;
                query.end_ms = 0.0;
                let path = self
                    .session_path
                    .clone()
                    .expect("reanalysis has source path");
                self.apply_loaded_session(path, loaded);
                self.query = query;
                self.invalidate_query();
                self.status = format!(
                    "Reanalysis ready · {} detailed I/O · {:.0} ms",
                    self.analyzer.completed_ios().len(),
                    self.reanalysis.elapsed_ms
                );
            }
            Err(error) => {
                self.phase = CapturePhase::Complete;
                self.status = "Reanalysis failed · previous view preserved".into();
                self.reanalysis.error = Some(error);
            }
        }
    }

    fn reanalysis_ui(&mut self, ui: &mut egui::Ui) {
        self.poll_reanalysis();
        if self.session_path.is_none() {
            return;
        }
        if !self.is_running() && self.reanalysis.source_start_ns.is_none() {
            let summary = self.analyzer.live_summary();
            let origin = self.time_origin();
            self.reanalysis.source_start_ns = Some(origin);
            self.reanalysis.source_end_ns = self.analyzer.scheduler_waits().iter().map(|w|w.ts_ns).max().unwrap_or(0).max(self.analyzer.session_start_ns().unwrap_or(origin).saturating_add(summary.logging_ns));
            self.reanalysis.source_count = summary.completed_ios;
            self.reanalysis.draft = ["0".into(), (self.reanalysis.source_end_ns.saturating_sub(origin) as f64 / 1e6).to_string()];
        }
        let Some(origin) = self.reanalysis.source_start_ns else {
            return;
        };
        let retained = self.analyzer.completed_ios().len();
        if self.reanalysis.window.is_some() || self.reanalysis.source_count > retained as u64 {
            ui.label(format!(
                "Original session: {} I/O · loaded detail: {retained} · {}",
                self.reanalysis.source_count,
                self.reanalysis.window.map_or_else(
                    || "recent detail window; use Reanalyze time range for older data".into(),
                    |(a, b)| format!(
                        "completion {:.3}–{:.3} ms",
                        (a - origin) as f64 / 1e6,
                        (b - origin) as f64 / 1e6
                    )
                )
            ));
        }
        egui::CollapsingHeader::new("Reanalyze time range · recover older detail from original session")
.open((self.render_qa.output.is_some()&&std::env::var_os("ANDROID_EBPF_QA_REANALYSIS").is_some()).then_some(true))
            .show(ui,|ui| {
                ui.label(format!("Source span: 0–{:.3} ms · maximum 100,000 I/O or scheduler wait events per detail window",self.reanalysis.source_end_ns.saturating_sub(origin)as f64/1e6));
                ui.horizontal_wrapped(|ui| {
                    for (i,label) in ["Start (ms)","End (ms)"].iter().enumerate() {
                        let response=ui.label(*label);
                        ui.add(egui::TextEdit::singleline(&mut self.reanalysis.draft[i]).desired_width(100.0)).labelled_by(response.id);
                    }
                    let apply=ui.add_enabled(!self.is_running(),egui::Button::new("Reanalyze interval"));
                    self.render_qa.reanalysis_button=Some(apply.rect.center());
                    if apply.clicked() {match parse_reanalysis_range(&self.reanalysis.draft,origin) {Ok(range)=>self.begin_reanalysis(Some(range)),Err(error)=>self.reanalysis.error=Some(error)}}
                    let restore=ui.add_enabled(!self.is_running(),egui::Button::new("Restore full session"));
                    self.render_qa.reanalysis_restore_button=Some(restore.rect.center());
                    if restore.clicked(){self.begin_reanalysis(None);}
                    if self.reanalysis.pending.is_some() {
                        ui.spinner();
                        if ui.button("Cancel reanalysis").clicked() && let Some(cancel)=&self.reanalysis.cancel {cancel.store(true,Ordering::Relaxed);}
                    }
                });
                ui.label("Inclusive completion-time interval (accounting timestamp for scheduler waits). Original block ordering preserves access pattern and queue depth. File evidence is replayed from the same source. A larger/dense interval asks you to narrow it; previous analysis stays available on failure.");
                if let Some(error)=&self.reanalysis.error {ui.colored_label(red(),error);}
            });
    }
}
