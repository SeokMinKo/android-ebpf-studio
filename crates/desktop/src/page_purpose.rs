#[derive(Clone)]
enum FindingAction {
    Request(IoSelectionKey),
    Interval(u64),
    Issuer(u32),
    Unresolved,
}

#[cfg(test)]
mod page_purpose_tests {
    use super::*;
    use android_ebpf_protocol::{BlockComplete, BlockIssue, StorageEvent};
    fn fixture() -> AnalysisEngine {
        let mut e = AnalysisEngine::new();
        for (id, start, latency, pid, bytes) in [
            (1, 0, 10_000_000, 10, 4096),
            (2, 1_000_000_000, 100_000, 20, 65536),
            (3, 1_100_000_000, 200_000, 20, 65536),
        ] {
            e.ingest(StorageEvent::BlockIssue(BlockIssue {
                ts_ns: start,
                request_id: id,
                device_major: 8,
                device_minor: 0,
                sector: id * 8,
                sectors: bytes / 512,
                bytes,
                operation: IoOperation::Read,
                pid,
                tid: pid,
                comm: format!("process-{pid}"),
                cpu: 0,
            }));
            e.ingest(StorageEvent::BlockComplete(BlockComplete {
                ts_ns: start + latency,
                request_id: id,
                device_major: 8,
                device_minor: 0,
                status: 0,
            }));
        }
        e
    }
    #[test]
    fn activity_cache_reuses_frames_and_rebuilds_after_filter_and_session_reset() {
        let mut app = StudioApp {
            analyzer: fixture(),
            ..Default::default()
        };
        let ctx = egui::Context::default();
        let render = |app: &mut StudioApp| {
            let mut output = ctx.run_ui(Default::default(), |root| {
                egui::CentralPanel::default().show(root, |ui| app.trends_ui(ui));
            });
            output.textures_delta.clear();
        };
        render(&mut app);
        let original = Arc::clone(&app.trend_view.as_ref().unwrap().1);
        render(&mut app);
        assert!(Arc::ptr_eq(&original, &app.trend_view.as_ref().unwrap().1));
        assert_eq!(original.busiest_second, Some((1, [2.0, 0.0, 0.125, 0.0])));
        for (index, series) in original.activity_points.iter().enumerate() {
            let expected: Vec<_> = original
                .bins
                .iter()
                .map(|(&s, v)| egui_plot::PlotPoint::new(s as f64 + 0.5, v[index]))
                .collect();
            assert_eq!(series.full(), expected.as_slice());
        }
        app.query.pid = 10;
        app.invalidate_query();
        app.rebuild_filtered();
        render(&mut app);
        let filtered = &app.trend_view.as_ref().unwrap().1;
        assert!(!Arc::ptr_eq(&original, filtered));
        assert_eq!(filtered.coverage, [0, 0, 1]);
        assert_eq!(filtered.bins.len(), 1);
        assert_eq!(
            filtered.busiest_second,
            Some((0, [1.0, 0.0, 4096.0 / 1_048_576.0, 0.0]))
        );
        assert_eq!(original.coverage, [0, 0, 3]);
        assert_eq!(app.analyzer.completed_ios().len(), 3);
        app.reset_analysis();
        assert!(app.trend_view.is_none());
        render(&mut app);
        assert!(
            app.trend_view.is_none(),
            "empty next session cannot reuse old bins"
        );
    }

    #[test]
    fn activity_click_populates_summary_for_the_interval_and_preserves_other_filters() {
        let mut app = StudioApp {
            analyzer: fixture(),
            ..Default::default()
        };
        app.query.pid = 20;
        app.query.operation = Some(IoOperation::Read);
        app.explore_activity_second(1.0);
        let deadline = Instant::now() + Duration::from_secs(3);
        while app.selection.pending.is_some() {
            app.poll_selection();
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert_eq!(app.page, Page::Explore);
        assert_eq!(app.query.pid, 20);
        assert_eq!(app.query.operation, Some(IoOperation::Read));
        let selected = &app
            .selection
            .summary
            .as_ref()
            .expect("time-bin click must fill Summary")
            .keys;
        assert_eq!(selected.len(), 2);
        assert!(
            app.analysis()
                .completed_ios()
                .iter()
                .all(|io| selected.contains(&selection_key(io)))
        );
        assert_eq!(app.analyzer.completed_ios().len(), 3);
    }

    #[test]
    fn overview_distinguishes_longest_request_busiest_interval_and_largest_issuer() {
        let d = TrendData::build(&fixture(), 0);
        assert_eq!(d.slowest.unwrap().issue.request_id, 1);
        assert_eq!(d.top_issuer, Some((20, "process-20".into(), 2, 131072)));
        assert_eq!(d.bins[&1], [2.0, 0.0, 0.125, 0.0]);
        assert_eq!(d.coverage, [0, 0, 3]);
    }
    #[test]
    fn overview_actions_keep_scope_and_open_the_exact_request() {
        let mut app = StudioApp {
            analyzer: fixture(),
            ..Default::default()
        };
        app.query.operation = Some(IoOperation::Read);
        app.open_finding(FindingAction::Interval(1));
        assert_eq!(app.page, Page::Explore);
        assert_eq!(app.analysis().completed_ios().len(), 2);
        assert_eq!(app.query.operation, Some(IoOperation::Read));
        let key = selection_key(&app.analysis().completed_ios()[0]);
        app.open_finding(FindingAction::Request(key));
        assert_eq!(app.page, Page::Investigate);
        assert_eq!(app.selected_pipeline_request, Some(key));
    }
    #[test]
    fn comparison_baseline_survives_next_capture_and_rejects_filtered_pin() {
        let mut app = StudioApp {
            analyzer: fixture(),
            ..Default::default()
        };
        app.pin_comparison();
        assert_eq!(app.comparison.as_ref().unwrap().summary.completed_ios, 3);
        app.reset_analysis();
        assert_eq!(app.comparison.as_ref().unwrap().summary.completed_ios, 3);
        app.analyzer = fixture();
        app.query.pid = 20;
        app.comparison = None;
        app.pin_comparison();
        assert!(app.comparison.is_none());
    }

    #[test]
    fn overview_painted_kpis_do_not_mix_last_kernel_snapshot_with_retained_io() {
        let mut app = StudioApp {
            analyzer: fixture(),
            ..Default::default()
        };
        app.latest_aggregate = Some(AggregateSnapshot {
            session_id: "test".into(),
            epoch: 1,
            config_generation: 0,
            start_ts_ns: 0,
            end_ts_ns: 1,
            counters: android_ebpf_protocol::AggregateCounters {
                observed: 987,
                ..Default::default()
            },
            histograms: vec![],
        });
        let ctx = egui::Context::default();
        let mut output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1200.0, 700.0),
                )),
                ..Default::default()
            },
            |root| {
                egui::CentralPanel::default().show(root, |ui| app.metrics_ui(ui));
            },
        );
        output.textures_delta.clear();
        fn text(shape: &egui::Shape, result: &mut Vec<String>) {
            match shape {
                egui::Shape::Text(t) => result.push(t.galley.job.text.clone()),
                egui::Shape::Vec(shapes) => {
                    for s in shapes {
                        text(s, result)
                    }
                }
                _ => {}
            }
        }
        let mut labels = Vec::new();
        for shape in output.shapes {
            text(&shape.shape, &mut labels);
        }
        assert!(
            !labels.iter().any(|s| s == "987"),
            "Kernel snapshot observed count was painted as completed I/O"
        );
        assert!(
            labels.iter().any(|s| s == "3"),
            "Retained completed I/O count missing"
        );
    }
}

impl StudioApp {
    fn open_finding(&mut self, action: FindingAction) {
        match action {
            FindingAction::Request(key) => {
                self.selected_pipeline_request = Some(key);
                self.page = Page::Investigate;
                return;
            }
            FindingAction::Interval(second) => {
                self.query.start_ms = second as f64 * 1000.0;
                self.query.end_ms = (second + 1) as f64 * 1000.0 - 0.000001;
            }
            FindingAction::Issuer(pid) => self.query.pid = pid,
            FindingAction::Unresolved => self.query.confidence = Some(PathConfidence::Unresolved),
        }
        self.invalidate_query();
        self.rebuild_filtered();
        self.page = Page::Explore;
    }

    fn summary_ui(&mut self, ui: &mut egui::Ui) {
        section_header(
            ui,
            "Overview · choose where to look",
            "Ranked observations in the current filters, followed by activity and distribution. Rankings are not proof of a fault.",
        );
        if self
            .trend_view
            .as_ref()
            .is_none_or(|(g, _)| *g != self.analysis_generation)
        {
            self.trend_view = Some((
                self.analysis_generation,
                Arc::new(TrendData::build(self.analysis(), self.time_origin())),
            ));
        }
        let data = &self.trend_view.as_ref().unwrap().1;
        let mut findings = Vec::new();
        if let Some(io) = &data.slowest {
            findings.push((
                "Longest I/O",
                format!(
                    "{} · {} · {} · {}",
                    format_latency(io.total_latency_ns),
                    io.issue.comm,
                    operation_label(io.issue.operation),
                    format_bytes(io.issue.bytes as u64)
                ),
                "Explain this I/O",
                FindingAction::Request(selection_key(io)),
            ));
        }
        if let Some((second, bin)) = data.busiest_second {
            findings.push((
                "Busiest second",
                format!(
                    "{}–{} s · {:.2} MiB/s · {:.0} Read/Write I/O",
                    second,
                    second + 1,
                    bin[2] + bin[3],
                    bin[0] + bin[1]
                ),
                "Explore interval",
                FindingAction::Interval(second),
            ));
        }
        if let Some((pid, name, count, bytes)) = &data.top_issuer {
            findings.push((
                "Largest block issuer",
                format!(
                    "{name} · PID {pid} · {} · {count} I/O",
                    format_bytes(*bytes)
                ),
                "Explore process",
                FindingAction::Issuer(*pid),
            ));
        }
        let total: u64 = data.coverage.iter().sum();
        if data.coverage[2] > 0 {
            findings.push((
                "FilePath gaps",
                format!(
                    "{} / {total} requests ({:.1}%) unresolved",
                    data.coverage[2],
                    ratio(data.coverage[2], total)
                ),
                "Explore unresolved",
                FindingAction::Unresolved,
            ));
        }
        for (title, detail, label, action) in findings {
            ui.horizontal_wrapped(|ui| {
                ui.strong(title);
                ui.label(detail);
                let response = ui.button(label);
                self.render_qa
                    .inspector_buttons
                    .insert(label.into(), response.rect.center());
                if response.clicked() {
                    self.open_finding(action);
                }
            });
            ui.separator();
        }
        ui.small("Block issuer may be a writeback worker. 1 s bins use completion time. FilePath ratios use retained completed request counts, not bytes.");
        ui.horizontal_wrapped(|ui| {
            ui.label(&self.loss_status);
            if ui.button("Check capture quality").clicked() {
                self.page = Page::Diagnostics;
            }
            if ui.button("Compare with another run").clicked() {
                self.page = Page::Compare;
            }
        });
        ui.add_space(10.0);
        self.metrics_ui(ui);
        if let Some(snapshot) = &self.latest_aggregate {
            ui.collapsing("Last kernel aggregate · separate snapshot scope",|ui| {
                ui.label(format!("Epoch {} · {}–{} ns · observed {} · bytes {}",snapshot.epoch,snapshot.start_ts_ns,snapshot.end_ts_ns,snapshot.counters.observed,format_bytes(snapshot.counters.bytes)));
                ui.label(format!("P95 approximate histogram: {}",format_latency(aggregate_percentile(snapshot,HistogramMetric::TotalLatency,95))));
                ui.small("Snapshot observed count is not the retained completed-I/O count. Epoch boundaries and suppressed detail can differ.");
            });
        }
        ui.add_space(10.0);
        self.trends_ui(ui);
        ui.collapsing("Detailed session breakdown", |ui| {
            self.summary_breakdown_ui(ui)
        });
    }

    fn pin_comparison(&mut self) {
        if self.is_running() || self.query.active() || self.analyzer.completed_ios().is_empty() {
            return;
        }
        self.comparison = Some(ComparisonBaseline {
            viewer: Box::new(self.comparison_viewer()),
            path: self
                .session_path
                .clone()
                .unwrap_or_else(|| PathBuf::from("current-session")),
            summary: self.analysis_summary(),
            rejected_records: self.rejected_records,
            capabilities: self.capabilities.clone(),
        });
        self.compare_explore.needs_apply = true;
        self.compare_explore.fit = true;
        self.status = "Baseline kept in memory. Open or record the next session to compare.".into();
    }

    fn capture_quality_ui(&mut self, ui: &mut egui::Ui) {
        section_header(
            ui,
            "Diagnostics · can I trust this capture?",
            "Check missing measurements, data loss and collection failures before interpreting an I/O result.",
        );
        ui.label(format!(
            "Capture state: {} · {} accepted / {} rejected records",
            self.phase.label(),
            self.received_events,
            self.rejected_records
        ));
        ui.label(&self.loss_status);
        if !self.disk_stats.is_empty() {
            ui.colored_label(amber(),"Device counters only: individual I/O, FilePath and latency are not measured in this session.");
        }
        if let Some(error) = &self.capture_error {
            ui.colored_label(red(), error);
        }
        if let Some(capabilities) = &self.capabilities {
            for plan in capabilities
                .attach_plan
                .iter()
                .filter(|p| p.state == CapabilityState::Unavailable)
                .take(8)
            {
                ui.small(format!(
                    "{} · {}: {}",
                    pipeline_layer_label(plan.layer),
                    plan.event_or_function,
                    plan.reason.as_deref().unwrap_or("No reason reported")
                ));
            }
        } else {
            ui.label("Probe capability report unavailable for this session.");
        }
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    !self.is_running() && self.selected_serial.is_some(),
                    egui::Button::new("Inspect connected phone"),
                )
                .clicked()
            {
                self.preflight();
            }
            if ui.button("Explore unresolved FilePath").clicked() {
                self.open_finding(FindingAction::Unresolved);
            }
        });
        for record in self
            .diagnostics
            .iter()
            .rev()
            .filter(|r| matches!(r.level, DiagnosticLevel::Error | DiagnosticLevel::Warn))
            .take(3)
        {
            ui.label(format!(
                "{:?} · {} · {}",
                record.level,
                record.code,
                record.detail.as_deref().unwrap_or(&record.event)
            ));
        }
        ui.separator();
    }
}
