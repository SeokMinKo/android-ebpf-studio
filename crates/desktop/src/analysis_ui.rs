// Shared query for all request-oriented analysis surfaces. Capture filters are
// intentionally separate: these controls never discard incoming measurements.
#[cfg(test)]
mod diskstats_performance_tests {
    use super::*;

    fn snapshot(boot: &str, second: u64, counters: u64) -> WireRecord {
        WireRecord::DiskStats {
            schema_version: android_ebpf_protocol::SCHEMA_VERSION,
            boot_id: boot.into(),
            elapsed_ms: second * 1000,
            raw: format!("253 0 dm-0 {counters} 0 {counters} 0 {counters} 0 {counters} 0 0 0 0\n"),
        }
    }

    #[test]
    fn counter_projection_preserves_deltas_without_double_counting() {
        let mut view = DiskStatsView::default();
        let mut records = vec![snapshot("a", 0, 10), snapshot("a", 1, 20)];
        view.sync(&records);
        assert_eq!(view.totals["253:0 dm-0"], [10; 4]);
        view.sync(&records);
        assert_eq!(view.samples["253:0 dm-0"].len(), 1);
        records.push(snapshot("a", 2, 25));
        view.sync(&records);
        assert_eq!(view.totals["253:0 dm-0"], [15; 4]);
        assert_eq!(view.samples["253:0 dm-0"][1].y, 10.0 * 512.0 / 1_048_576.0);
        // Reboot with larger counters must not create an artificial spike.
        records.push(snapshot("b", 3, 1000));
        records.push(snapshot("b", 4, 1002));
        records.push(snapshot("b", 5, 1));
        view.sync(&records);
        assert_eq!(view.totals["253:0 dm-0"], [17; 4]);
        assert_eq!(view.reset_intervals, 2);
        let mut missing = snapshot("b", 6, 2);
        if let WireRecord::DiskStats { raw, .. } = &mut missing {
            raw.clear();
        }
        records.extend([missing, snapshot("b", 7, 100), snapshot("b", 8, 101)]);
        view.sync(&records);
        assert_eq!(view.totals["253:0 dm-0"], [18; 4]);
    }

    #[test]
    fn new_session_discards_counter_projection() {
        let mut app = StudioApp {
            disk_stats: vec![snapshot("a", 0, 10), snapshot("a", 1, 20)],
            ..StudioApp::default()
        };
        app.disk_stats_view.sync(&app.disk_stats);
        app.reset_analysis();
        app.disk_stats = vec![snapshot("b", 0, 100), snapshot("b", 1, 103)];
        app.disk_stats_view.sync(&app.disk_stats);
        assert_eq!(app.disk_stats_view.totals["253:0 dm-0"], [3; 4]);
    }

    #[test]
    fn pending_analysis_does_not_rebuild_partial_results() {
        let mut app = StudioApp {
            session_path: Some(PathBuf::from("test-session.ndjson")),
            ..StudioApp::default()
        };
        app.tx.send(HostMessage::AnalysisStarted).unwrap();
        app.drain_messages();
        let ctx = egui::Context::default();
        let mut output = ctx.run_ui(Default::default(), |root| {
            egui::CentralPanel::default().show(root, |ui| app.analysis_page_ui(ui));
        });
        output.textures_delta.clear();
        assert!(
            app.summary_view.is_none(),
            "pending batches must not rebuild results on every frame"
        );
        app.tx.send(HostMessage::Finalized(Ok(None))).unwrap();
        app.drain_messages();
        let mut output = ctx.run_ui(Default::default(), |root| {
            egui::CentralPanel::default().show(root, |ui| app.analysis_page_ui(ui));
        });
        output.textures_delta.clear();
        assert_eq!(app.phase, CapturePhase::Complete);
        assert!(
            app.summary_view.is_some(),
            "final results must appear automatically"
        );
    }

    #[test]
    #[ignore = "manual host performance probe; run with --ignored --nocapture"]
    fn repeated_live_counter_render() {
        let mut app = StudioApp::default();
        for second in 0..600 {
            let raw = (0..64)
                .map(|dev| {
                    format!(
                        "253 {dev} dm-{dev} {} 0 {} 0 {} 0 {} 0 0 0 0\n",
                        second * 10,
                        second * 80,
                        second * 5,
                        second * 40
                    )
                })
                .collect::<String>();
            app.disk_stats.push(WireRecord::DiskStats {
                schema_version: android_ebpf_protocol::SCHEMA_VERSION,
                boot_id: "fixture-boot".into(),
                elapsed_ms: second * 1000,
                raw,
            });
        }
        let ctx = egui::Context::default();
        let mut timings = Vec::new();
        for frame in 0..12 {
            let start = Instant::now();
            let mut output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1200.0, 800.0),
                    )),
                    ..Default::default()
                },
                |root| {
                    egui::CentralPanel::default().show(root, |ui| {
                        egui::ScrollArea::vertical().show(ui, |ui| app.diskstats_ui(ui));
                    });
                },
            );
            output.textures_delta.clear();
            if frame >= 2 {
                timings.push(start.elapsed().as_secs_f64() * 1000.0);
            }
        }
        timings.sort_by(f64::total_cmp);
        eprintln!(
            "diskstats warm render: median {:.3} ms, max {:.3} ms",
            timings[5], timings[9]
        );
        assert!(
            timings[5] < 40.0,
            "live counter screen blocks repeated frames: {timings:?}"
        );
    }
}

#[derive(Debug, Clone, PartialEq, Default, serde::Serialize)]
struct AnalysisFilter {
    latency_range: Option<LatencyRange>,
    request_keys: Option<std::collections::HashSet<IoSelectionKey>>,
    start_ms: f64,
    end_ms: f64,
    pid: u32,
    tid: u32,
    process: String,
    file: String,
    device: String,
    operation: Option<IoOperation>,
    confidence: Option<PathConfidence>,
}

type PathConfidence = android_ebpf_protocol::FilePathConfidence;

fn path_confidence(origins: &[FileOriginView]) -> PathConfidence {
    PathConfidence::from_origins(origins)
}

impl AnalysisFilter {
    fn active(&self) -> bool {
        self != &Self::default()
    }
    fn matches(&self, engine: &AnalysisEngine, io: &CompletedIo, origin: u64) -> bool {
        if self
            .latency_range
            .is_some_and(|range| !range.contains(io.total_latency_ns))
        {
            return false;
        }
        if self
            .request_keys
            .as_ref()
            .is_some_and(|keys| !keys.contains(&selection_key(io)))
        {
            return false;
        }
        if (self.start_ms > 0.0 || self.end_ms > 0.0)
            && io.completion_timestamp().is_none_or(|ts| {
                let time = ts.saturating_sub(origin) as f64 / 1_000_000.0;
                time < self.start_ms || (self.end_ms > 0.0 && time > self.end_ms)
            })
        {
            return false;
        }
        if (self.pid != 0 && Some(self.pid) != io.issuer_pid())
            || (self.tid != 0 && Some(self.tid) != io.issuer_tid())
            || self.operation.is_some_and(|v| v != io.issue.operation)
            || !io
                .issue
                .comm
                .to_lowercase()
                .contains(&self.process.to_lowercase())
            || (!self.device.is_empty()
                && self.device != format!("{}:{}", io.issue.device_major, io.issue.device_minor))
        {
            return false;
        }
        if self.file.is_empty() && self.confidence.is_none() {
            return true;
        }
        let origins = block_file_origins(&engine.transaction_for(io));
        self.confidence
            .is_none_or(|v| path_confidence(&origins) == v)
            && (self.file.is_empty()
                || origins.iter().any(|v| {
                    v.path
                        .as_ref()
                        .and_then(|p| p.path.as_ref())
                        .is_some_and(|p| p.to_lowercase().contains(&self.file.to_lowercase()))
                        || v.file.fallback_label().contains(&self.file)
                }))
    }
}

/// Append-only projection of the raw session snapshots. Reset with the session,
/// and never derive a delta across boots or a device's disappearance.
#[derive(Default)]
struct DiskStatsView {
    processed: usize,
    previous: Option<(String, u64, BTreeMap<String, [u64; 4]>)>,
    totals: BTreeMap<String, [u64; 4]>,
    samples: BTreeMap<String, Vec<egui_plot::PlotPoint>>,
    reset_intervals: usize,
}

impl DiskStatsView {
    fn sync(&mut self, records: &[WireRecord]) {
        if self.processed > records.len() {
            *self = Self::default();
        }
        for record in &records[self.processed..] {
            let WireRecord::DiskStats {
                boot_id,
                elapsed_ms,
                raw,
                ..
            } = record
            else {
                continue;
            };
            let current = parse_diskstats(raw);
            if let Some((boot, time, old)) = self.previous.as_ref() {
                if boot == boot_id && elapsed_ms > time {
                    let interval = (elapsed_ms - time) as f64 / 1000.0;
                    for (key, counters) in &current {
                        if let Some(before) = old.get(key) {
                            if let Some(delta) = disk_delta(before, counters) {
                                let sum = self.totals.entry(key.clone()).or_default();
                                for i in 0..4 {
                                    sum[i] = sum[i].saturating_add(delta[i]);
                                }
                                self.samples.entry(key.clone()).or_default().push(
                                    egui_plot::PlotPoint::new(
                                        *elapsed_ms as f64 / 1000.0,
                                        delta[1].saturating_add(delta[3]) as f64 * 512.0
                                            / 1_048_576.0
                                            / interval,
                                    ),
                                );
                            } else {
                                self.reset_intervals += 1;
                            }
                        }
                    }
                } else {
                    self.reset_intervals += 1;
                }
            }
            self.previous = Some((boot_id.clone(), *elapsed_ms, current));
        }
        self.processed = records.len();
    }
}

impl StudioApp {
    fn perfetto_pending(&self) -> bool {
        self.is_running() && self.source_info.last().is_some_and(|r| matches!(r, WireRecord::SourceInfo {source, metadata,..} if source=="perfetto" && metadata.get("stage").and_then(|s|s.as_str())==Some("recording")))
    }
    fn diskstats_ui(&mut self, ui: &mut egui::Ui) {
        section_header(
            ui,
            "Device counter analysis",
            "Fallback source: /proc/diskstats · cumulative block-device counters sampled approximately every second",
        );
        info_banner(
            ui,
            "These counters do not provide individual I/O, FilePath, PID/TID, latency percentiles or LBA. Device-mapper and partition rows can represent the same I/O; rows are never summed across devices.",
        );
        self.disk_stats_view.sync(&self.disk_stats);
        let DiskStatsView {
            totals,
            samples,
            reset_intervals,
            ..
        } = &self.disk_stats_view;
        ui.label(format!("{} snapshots · {} counter/clock-reset intervals excluded; new/disappearing devices have no inferred delta", self.disk_stats.len(), reset_intervals));
        egui::ScrollArea::horizontal().show(ui, |ui| {
            egui::Grid::new("diskstats-summary")
                .striped(true)
                .show(ui, |ui| {
                    for label in [
                        "Device",
                        "Read requests",
                        "Read bytes",
                        "Write requests",
                        "Write bytes",
                    ] {
                        ui.strong(label);
                    }
                    ui.end_row();
                    for (name, values) in totals {
                        ui.label(name);
                        ui.label(values[0].to_string());
                        ui.label(format_bytes(values[1].saturating_mul(512)));
                        ui.label(values[2].to_string());
                        ui.label(format_bytes(values[3].saturating_mul(512)));
                        ui.end_row();
                    }
                });
        });
        studio_plot("device-counter-throughput")
            .height(260.0)
            .legend(Legend::default())
            .x_axis_label("Host elapsed seconds")
            .y_axis_label("MiB/s · per device")
            .show(ui, |plot| {
                for (i, (name, points)) in samples.iter().enumerate() {
                    plot.line(
                        Line::new(name, points.as_slice())
                            .color([accent(), green(), amber(), red()][i % 4]),
                    );
                }
            });
    }

    fn analysis(&self) -> &AnalysisEngine {
        self.filtered.as_ref().unwrap_or(&self.analyzer)
    }

    fn known_time_origin(&self) -> Option<u64> {
        self.reanalysis
            .source_start_ns
            .or(self.analyzer.session_start_ns())
    }
    fn time_origin(&self) -> u64 {
        self.known_time_origin().unwrap_or(0)
    }

    fn invalidate_query(&mut self) {
        self.trend_view = None;
        self.selection = SelectionState {
            enabled: true,
            auto_bounds: true,
            ..Default::default()
        };
        self.filtered_generation = u64::MAX;
        self.summary_view = None;
        self.explorer_view = None;
        self.pipeline_view = None;
        self.selected_pipeline_request = None;
    }

    fn rebuild_filtered(&mut self) {
        if !self.query.active() {
            self.filtered = None;
            if self.filtered_generation != self.analysis_generation {
                self.update_file_evidence_scope();
                self.filtered_generation = self.analysis_generation;
            }
            return;
        }
        if self.filtered_generation == self.analysis_generation {
            return;
        }
        let origin = self.time_origin();
        self.filtered = Some(
            self.analyzer
                .select_completed(|io| self.query.matches(&self.analyzer, io, origin)),
        );
        self.update_file_evidence_scope();
        self.filtered_generation = self.analysis_generation;
    }

    fn filter_ui(&mut self, ui: &mut egui::Ui) {
        if self.analyzer.completed_ios().is_empty() {
            return;
        }
        let previous = self.query.clone();
        if let Some(range) = self.query.latency_range {
            ui.horizontal_wrapped(|ui| {
                ui.label(format!("Total latency: {}", range.label()));
                if ui.button("Clear latency range").clicked() {
                    self.query.latency_range = None;
                }
            });
        }
        ui.collapsing("Analysis filters · shared across Overview, Explore and Investigate", |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label("Completion time (ms)");
                ui.add(egui::DragValue::new(&mut self.query.start_ms).prefix("From ").range(0.0..=f64::MAX));
                ui.add(egui::DragValue::new(&mut self.query.end_ms).prefix("To ").range(0.0..=f64::MAX));
                ui.label("To 0 = session end");
                ui.add(egui::DragValue::new(&mut self.query.pid).prefix("PID "));
                ui.add(egui::DragValue::new(&mut self.query.tid).prefix("TID "));
                ui.label("0 = all");
                egui::ComboBox::from_id_salt("analysis-op").selected_text(self.query.operation.map_or("All operations", operation_label)).show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.query.operation, None, "All operations");
                    for op in [IoOperation::Read, IoOperation::Write] { ui.selectable_value(&mut self.query.operation, Some(op), operation_label(op)); }
                });
                egui::ComboBox::from_id_salt("analysis-confidence").selected_text(self.query.confidence.map_or("All FilePath confidence".into(), |v| format!("{v:?}"))).show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.query.confidence, None, "All FilePath confidence");
                    for value in [PathConfidence::Exact, PathConfidence::Probable, PathConfidence::Unresolved] { ui.selectable_value(&mut self.query.confidence, Some(value), format!("{value:?}")); }
                });
            });
            ui.horizontal_wrapped(|ui| {
                ui.label("Process"); ui.add(egui::TextEdit::singleline(&mut self.query.process).desired_width(100.0));
                ui.label("FilePath / inode"); ui.add(egui::TextEdit::singleline(&mut self.query.file).desired_width(220.0));
                ui.label("Device major:minor"); ui.add(egui::TextEdit::singleline(&mut self.query.device).desired_width(80.0));
                if ui.button("Clear filters").clicked() { self.query = AnalysisFilter::default(); }
            });
            ui.label("Selection uses the loaded completed-request window; file-operation evidence follows that cohort. Capture diagnostics and Compare baseline remain session-wide. File candidates are preserved together. Sequential/random classification remains from the original device/direction stream.");
        });
        if previous != self.query {
            self.invalidate_query();
        }
        if self.query.active() {
            ui.label(self.query.request_keys.as_ref().map_or_else(
                || "Filters active".to_string(),
                |keys| {
                    format!(
                        "Filters active · {} explicitly selected request identities",
                        keys.len()
                    )
                },
            ));
        }
        self.time_filter_scope_ui(ui);
    }

    fn time_filter_scope_ui(&self, ui: &mut egui::Ui) {
        if self.query.start_ms > 0.0 || self.query.end_ms > 0.0 {
            let count = self.analyzer.live_summary().unplaced_time_ios;
            if count > 0 {
                ui.label(format!("Time filter excludes unsupported-clock I/O ({count} in the loaded source). Clear the time filter to inspect their count, bytes and addresses."));
            }
        }
    }

    fn trends_ui(&mut self, ui: &mut egui::Ui) {
        if self.analysis().completed_ios().is_empty() {
            return;
        }
        section_header(
            ui,
            "I/O activity",
            "Retained completed requests · fixed 1 s bins by completion time · click a time bin to inspect that interval",
        );
        let origin = self.time_origin();
        if self
            .trend_view
            .as_ref()
            .is_none_or(|(generation, _)| *generation != self.analysis_generation)
        {
            self.trend_view = Some((
                self.analysis_generation,
                Arc::new(TrendData::build(self.analysis(), origin)),
            ));
        }
        let data = Arc::clone(&self.trend_view.as_ref().unwrap().1);
        let TrendData {
            bins,
            activity_points,
            histogram,
            coverage,
            multi,
            targets,
            unplaced_time_count,
            ..
        } = &*data;
        self.session_file_path_coverage_ui(ui);
        let total: u64 = coverage.iter().sum();
        if *unplaced_time_count > 0 {
            ui.label(format!("{unplaced_time_count} / {total} I/O have no supported session clock. Time graphs and time filters exclude them; count, bytes, address and FilePath coverage retain them."));
        }
        ui.label(format!("Retained detail FilePath by request count (n={total}): Exact {} · Probable {} · Unresolved {} · multi-origin {multi}", coverage_percent(coverage[0],total), coverage_percent(coverage[1],total), coverage_percent(coverage[2],total)));
        ui.label("FilePath confidence requires a path snapshot as well as identity evidence. Exact inode without a path remains FilePath Unresolved. This ratio describes retained detail, not bytes or suppressed/unpaired I/O.");
        if let Some(aggregate) = &self.latest_aggregate {
            ui.label(format!("Last kernel snapshot observed: {} · retained completed: {} · lost/suppressed I/O are outside observed-completion FilePath coverage", aggregate.counters.observed, self.analyzer.completed_ios().len()));
        }
        let mut selected_bin = None;
        for (id, title, offset) in [
            ("iops-timeline", "IOPS (requests / s)", 0),
            ("throughput-timeline", "Throughput (MiB / s)", 2),
        ] {
            if bins.is_empty() {
                ui.label(format!(
                    "{title}: unavailable — no I/O can be placed on the session timeline."
                ));
                continue;
            }
            let mut rendered = [0usize; 2];
            let qa_gesture = self
                .render_qa
                .output
                .as_ref()
                .and_then(|_| std::env::var("ANDROID_EBPF_QA_GESTURE").ok());
            let qa_active = qa_gesture.as_deref().is_some_and(|g| {
                g.starts_with("activity-")
                    && (offset == if g == "activity-throughput" { 2 } else { 0 })
            });
            if qa_active && self.render_qa.frames >= 28 && self.render_qa.input_step == 0 {
                ui.scroll_to_rect(
                    egui::Rect::from_min_size(
                        ui.cursor().min,
                        egui::vec2(ui.available_width(), 200.0),
                    ),
                    Some(egui::Align::Center),
                );
            }
            let clip = ui.clip_rect();
            studio_plot(id)
                .include_x(activity_points[offset].full().first().unwrap().x)
                .include_x(activity_points[offset].full().last().unwrap().x)
                .include_y(
                    activity_points[offset].y_bounds[0]
                        .min(activity_points[offset + 1].y_bounds[0]),
                )
                .include_y(
                    activity_points[offset].y_bounds[1]
                        .max(activity_points[offset + 1].y_bounds[1]),
                )
                .height(170.0)
                .legend(Legend::default())
                .x_axis_label("Seconds since session start")
                .y_axis_label(title)
                .show(ui, |plot| {
                    for (index, label, color) in [(0, "Read", accent()), (1, "Write", green())] {
                        let bounds = plot.plot_bounds();
                        let columns = (plot.response().rect.width() * plot.ctx().pixels_per_point())
                            .ceil() as usize;
                        let samples = activity_points[offset + index]
                            .visible([bounds.min()[0], bounds.max()[0]], columns);
                        rendered[index] = samples.len();
                        if qa_active {
                            self.render_qa.activity.visible_points[index] = samples
                                .iter()
                                .filter(|p| {
                                    p.x >= bounds.min()[0]
                                        && p.x <= bounds.max()[0]
                                        && p.y >= bounds.min()[1]
                                        && p.y <= bounds.max()[1]
                                })
                                .count();
                        }
                        if qa_active && index == 0 {
                            let qa = &mut self.render_qa.activity;
                            let rect = plot.response().rect;
                            if qa.rect == Some(rect) {
                                qa.stable_frames += 1;
                            } else {
                                qa.rect = Some(rect);
                                qa.stable_frames = 0;
                            }
                            qa.origin_ns = origin;
                            qa.full_bins = bins.len();
                            qa.width = bounds.max()[0] - bounds.min()[0];
                            qa.mean_spacing =
                                samples.first().zip(samples.last()).map_or(0.0, |(a, b)| {
                                    (b.x - a.x) / samples.len().saturating_sub(1).max(1) as f64
                                });
                            if self.render_qa.input_step == 0 {
                                let original = activity_points[offset].full();
                                let middle = original[original.len() / 2];
                                let target = plot.screen_from_plot(middle);
                                qa.target = (rect.contains(target) && clip.contains(target))
                                    .then_some(target);
                                qa.expected_second = Some(middle.x.floor() as u64);
                            }
                        }
                        plot.points(Points::new(label, samples).radius(4.0).color(color));
                    }
                    if plot.response().clicked()
                        && let Some(point) = plot.pointer_coordinate()
                        && point.x >= 0.0
                    {
                        selected_bin = Some(point.x.floor());
                    }
                });
            if qa_active {
                self.render_qa.activity.rendered_points = rendered;
            }
            if rendered.iter().any(|&n| n < bins.len()) {
                ui.label(format!("Displayed time-bin points: Read {} / {} · Write {} / {} · first/min/max/last samples. Zoom for finer detail; analysis uses all bins.", rendered[0], bins.len(), rendered[1], bins.len()));
            }
        }
        if let Some(second) = selected_bin {
            self.explore_activity_second(second);
        }
        if let Some(range) = self.latency_distribution_ui(ui, histogram, total) {
            self.explore_latency_range(range);
        }
        ui.label("Total latency: insert→complete when insert exists, otherwise issue→complete. Queue: insert→issue (unavailable without insert). Device: issue→complete. Queue depth is observed block in-flight depth; missing/suppressed events can reduce it. Sequential: previous sector + sectors equals current sector, within the same device and direction, at the block issue layer.");
        ui.collapsing("Processes ranked by transferred bytes in selection", |ui| {
            let mut rows: Vec<_> = targets.iter().collect();
            rows.sort_by_key(|(_, v)| std::cmp::Reverse(v.1));
            for (name, (count, bytes)) in rows.into_iter().take(30) {
                ui.label(format!(
                    "{name} · {count} requests · {}",
                    format_bytes(*bytes)
                ));
            }
        });
    }
}

fn parse_diskstats(raw: &str) -> BTreeMap<String, [u64; 4]> {
    raw.lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 14 {
                return None;
            }
            Some((
                format!("{}:{} {}", fields[0], fields[1], fields[2]),
                [
                    fields[3].parse().ok()?,
                    fields[5].parse().ok()?,
                    fields[7].parse().ok()?,
                    fields[9].parse().ok()?,
                ],
            ))
        })
        .collect()
}

fn disk_delta(before: &[u64; 4], after: &[u64; 4]) -> Option<[u64; 4]> {
    Some([
        after[0].checked_sub(before[0])?,
        after[1].checked_sub(before[1])?,
        after[2].checked_sub(before[2])?,
        after[3].checked_sub(before[3])?,
    ])
}

#[cfg(test)]
mod query_regressions {
    use super::*;

    #[test]
    fn unwritable_session_target_enters_error_without_starting_capture() {
        let mut app = StudioApp::default();
        assert!(!app.create_session_at(std::env::temp_dir()));
        assert_eq!(app.phase, CapturePhase::Error);
        assert!(app.writer.is_none());
        assert!(app.capture.is_none());
        assert!(app.status.contains("retry Start"));
    }
    use android_ebpf_protocol::{
        BlockComplete, BlockIssue, FileIdentity, PathSnapshot, PathSource, StorageEvent,
    };

    fn engine() -> AnalysisEngine {
        let mut engine = AnalysisEngine::new();
        for id in 1..=3 {
            engine.ingest(StorageEvent::BlockIssue(BlockIssue {
                ts_ns: id * 1_000_000,
                request_id: id,
                device_major: 8,
                device_minor: 0,
                sector: id * 8,
                sectors: 8,
                bytes: 4096,
                operation: IoOperation::Read,
                pid: id as u32,
                tid: 10 + id as u32,
                cpu: 0,
                comm: format!("worker{id}"),
            }));
            engine.ingest(StorageEvent::BlockComplete(BlockComplete {
                ts_ns: id * 1_000_000 + 100_000,
                request_id: id,
                device_major: 8,
                device_minor: 0,
                status: 0,
            }));
        }
        engine
    }

    #[test]
    fn overview_metrics_match_retained_graph_cohort_after_eviction() {
        let seed = engine().completed_ios()[0].clone();
        let mut app = StudioApp::default();
        for id in 0..100_001u64 {
            let mut io = seed.clone();
            io.issue.request_id = id;
            io.issue.ts_ns = id * 10_000_000;
            io.completion.ts_ns = io.issue.ts_ns + if id < 10_000 { 5_000_000 } else { 100_000 };
            io.completion.request_id = id;
            io.total_latency_ns = Some(io.completion.ts_ns - io.issue.ts_ns);
            io.issue.bytes = if id < 10_000 { 65_536 } else { 4096 };
            io.issue.operation = if id.is_multiple_of(2) {
                IoOperation::Read
            } else {
                IoOperation::Write
            };
            app.analyzer
                .ingest(StorageEvent::ObservedBlockCompletion(io));
        }
        app.rebuild_filtered();
        let summary = app.analysis_summary();
        let detail = app.analysis().completed_ios();
        assert_eq!(detail.len(), 90_001);
        assert_eq!(
            summary.completed_ios,
            detail.len() as u64,
            "Overview KPI must describe the same requests as its graphs"
        );
        assert_eq!(
            summary.read_bytes,
            detail
                .iter()
                .filter(|io| io.issue.operation == IoOperation::Read)
                .map(|io| io.issue.bytes as u64)
                .sum::<u64>()
        );
        assert_eq!(
            summary.write_bytes,
            detail
                .iter()
                .filter(|io| io.issue.operation == IoOperation::Write)
                .map(|io| io.issue.bytes as u64)
                .sum::<u64>()
        );
        assert_eq!(summary.p95_latency_ns, Some(100_000));
        assert_eq!(
            summary
                .category_summaries
                .iter()
                .map(|c| c.completed_ios)
                .sum::<u64>(),
            detail.len() as u64
        );
        app.query.operation = Some(IoOperation::Write);
        app.invalidate_query();
        app.rebuild_filtered();
        let filtered = app.analysis_summary();
        assert_eq!(filtered.completed_ios, 45_000);
        assert_eq!(filtered.read_bytes, 0);
        assert_eq!(filtered.write_bytes, 45_000 * 4096);
        assert_eq!(
            app.analyzer.summary().completed_ios,
            100_001,
            "Original session totals remain available for export"
        );
    }

    #[test]
    fn projection_preserves_original_sequential_classification_and_latency() {
        let engine = engine();
        let selected = engine.select_completed(|io| io.issue.pid == 2);
        assert_eq!(selected.completed_ios().len(), 1);
        assert_eq!(
            selected.completed_ios()[0].access_pattern,
            AccessPattern::Sequential
        );
        assert_eq!(selected.summary().read_bytes, 4096);
        assert_eq!(selected.summary().p95_latency_ns, Some(100_000));
        assert_eq!(engine.completed_ios().len(), 3);
    }

    #[test]
    fn common_filter_conjoins_time_thread_process_device_operation_and_confidence() {
        let engine = engine();
        let query = AnalysisFilter {
            start_ms: 1.0,
            end_ms: 1.1,
            pid: 2,
            tid: 12,
            process: "WORKER2".into(),
            device: "8:0".into(),
            operation: Some(IoOperation::Read),
            confidence: Some(PathConfidence::Unresolved),
            ..Default::default()
        };
        let selected = engine.select_completed(|io| query.matches(&engine, io, 1_100_000));
        assert_eq!(selected.completed_ios().len(), 1);
        assert_eq!(selected.completed_ios()[0].issue.request_id, 2);
        let mut wrong = query;
        wrong.file = "/wrong-phone-file".into();
        assert!(
            engine
                .completed_ios()
                .iter()
                .all(|io| !wrong.matches(&engine, io, 1_100_000))
        );
    }

    #[test]
    fn exact_identity_without_path_is_unresolved_and_mixed_candidates_stay_uncertain() {
        let identity = FileIdentity {
            fs_device_major: 8,
            fs_device_minor: 1,
            inode: 42,
            inode_generation: None,
            mount_id: None,
        };
        let mut origin = FileOriginView {
            incomplete: false,
            file: identity,
            path: None,
            confidence: EdgeConfidence::Exact,
        };
        assert_eq!(
            path_confidence(&[origin.clone()]),
            PathConfidence::Unresolved
        );
        origin.path = Some(PathSnapshot {
            path: Some("/known".into()),
            captured_ts_ns: 1,
            source: PathSource::ProcFd,
            deleted: false,
        });
        assert_eq!(path_confidence(&[origin.clone()]), PathConfidence::Exact);
        let mut uncertain = origin.clone();
        uncertain.confidence = EdgeConfidence::Probable;
        assert_eq!(
            path_confidence(&[origin, uncertain]),
            PathConfidence::Probable
        );
    }

    #[test]
    fn diskstats_uses_sector_counters_and_rejects_resets_instead_of_false_zero() {
        let parsed = parse_diskstats("8 0 sda 10 0 80 1 20 0 160 2 0 3 4\nmalformed");
        assert_eq!(parsed["8:0 sda"], [10, 80, 20, 160]);
        assert_eq!(
            disk_delta(&[10, 80, 20, 160], &[12, 96, 21, 168]),
            Some([2, 16, 1, 8])
        );
        assert_eq!(disk_delta(&[10, 80, 20, 160], &[1, 8, 1, 8]), None);
    }

    #[test]
    fn stop_remains_busy_until_writer_finalizes_and_duplicate_start_is_ignored() {
        let mut app = StudioApp {
            phase: CapturePhase::Recording,
            ..Default::default()
        };
        let stop = Arc::new(AtomicBool::new(false));
        app.simulator_stop = Some(stop.clone());
        app.stop();
        assert_eq!(app.phase, CapturePhase::Stopping);
        assert!(app.is_running());
        app.start_simulator();
        assert!(Arc::ptr_eq(app.simulator_stop.as_ref().unwrap(), &stop));
        app.stop();
        assert_eq!(app.phase, CapturePhase::Stopping);
        app.tx.send(HostMessage::Ended(Ok(()))).unwrap();
        app.drain_messages();
        assert!(!app.is_running());
        assert_eq!(app.page, Page::Overview);
    }

    #[test]
    fn reset_clears_phone_specific_paths_and_filter_state() {
        let mut app = StudioApp {
            analyzer: engine(),
            query: AnalysisFilter {
                file: "old-phone".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        app.rebuild_filtered();
        app.reset_analysis();
        assert!(app.analyzer.completed_ios().is_empty());
        assert!(!app.query.active());
        assert!(app.filtered.is_none());
    }
}

include!("activity_series.rs");
include!("activity_qa.rs");

impl StudioApp {
    fn explore_activity_second(&mut self, second: f64) {
        self.query.start_ms = second * 1000.0;
        self.query.end_ms = (second + 1.0) * 1000.0 - 0.000001;
        self.invalidate_query();
        self.rebuild_filtered();
        self.page = Page::Explore;
        self.begin_selection(all_plot_requests());
    }
}

struct TrendData {
    slowest: Option<CompletedIo>,
    top_issuer: Option<(u32, String, u64, u64)>,
    bins: BTreeMap<u64, [f64; 4]>,
    activity_points: [ActivitySeries; 4],
    busiest_second: Option<(u64, [f64; 4])>,
    histogram: BTreeMap<u32, u64>,
    coverage: [u64; 3],
    multi: u64,
    targets: BTreeMap<String, (u64, u64)>,
    unplaced_time_count: u64,
}
impl TrendData {
    fn build(engine: &AnalysisEngine, origin: u64) -> Self {
        let mut slowest: Option<CompletedIo> = None;
        let mut issuers = BTreeMap::<u32, (String, u64, u64)>::new();
        let mut bins = BTreeMap::<u64, [f64; 4]>::new();
        let mut histogram = BTreeMap::<u32, u64>::new();
        let mut coverage = [0_u64; 3];
        let mut multi = 0;
        let mut targets = BTreeMap::<String, (u64, u64)>::new();
        let mut unplaced_time_count = 0;
        for io in engine.completed_ios() {
            if io.total_latency_ns.is_some()
                && slowest
                    .as_ref()
                    .is_none_or(|s| s.total_latency_ns < io.total_latency_ns)
            {
                slowest = Some(io.clone());
            }
            if let Some(pid) = io.issuer_pid() {
                let issuer = issuers
                    .entry(pid)
                    .or_insert_with(|| (io.issue.comm.clone(), 0, 0));
                issuer.1 += 1;
                issuer.2 += io.issue.bytes as u64;
            }
            if let Some(timestamp) = io.completion_timestamp() {
                let second = timestamp.saturating_sub(origin) / 1_000_000_000;
                let bin = bins.entry(second).or_default();
                let offset = usize::from(io.issue.operation == IoOperation::Write);
                if matches!(io.issue.operation, IoOperation::Read | IoOperation::Write) {
                    bin[offset] += 1.0;
                    bin[2 + offset] += io.issue.bytes as f64 / 1_048_576.0;
                }
            } else {
                unplaced_time_count += 1;
            }
            if let Some(latency) = io.total_latency_ns {
                let bucket = latency_bucket(latency);
                *histogram.entry(bucket).or_default() += 1;
            }
            let origins = block_file_origins(&engine.transaction_for(io));
            let idx = match path_confidence(&origins) {
                PathConfidence::Exact => 0,
                PathConfidence::Probable => 1,
                PathConfidence::Unresolved => 2,
            };
            coverage[idx] += 1;
            if origins.len() > 1 {
                multi += 1;
            }
            let name = issuer_label(io.issuer_pid(), io.issuer_tid(), &io.issue.comm);
            let target = targets.entry(name).or_default();
            target.0 += 1;
            target.1 += io.issue.bytes as u64;
        }

        let activity_points = std::array::from_fn(|index| {
            ActivitySeries::new(
                bins.iter()
                    .map(|(&second, values)| {
                        egui_plot::PlotPoint::new(second as f64 + 0.5, values[index])
                    })
                    .collect(),
            )
        });
        let busiest_second = bins
            .iter()
            .max_by(|a, b| (a.1[2] + a.1[3]).total_cmp(&(b.1[2] + b.1[3])))
            .map(|(&second, &values)| (second, values));
        Self {
            activity_points,
            busiest_second,
            slowest,
            top_issuer: issuers
                .into_iter()
                .max_by_key(|(_, v)| v.2)
                .map(|(pid, (name, count, bytes))| (pid, name, count, bytes)),
            bins,
            histogram,
            coverage,
            multi,
            targets,
            unplaced_time_count,
        }
    }
}

impl StudioApp {
    fn analysis_page_ui(&mut self, ui: &mut egui::Ui) {
        if matches!(self.phase, CapturePhase::Stopping | CapturePhase::Analyzing)
            && self.page != Page::Diagnostics
        {
            section_header(
                ui,
                "Preparing analysis",
                "Saving the session and processing remaining observations",
            );
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(&self.status);
            });
            ui.label(format!(
                "{} records received · {} completed I/O retained · {} queued messages",
                self.received_events,
                self.analyzer.completed_ios().len(),
                self.rx.len()
            ));
            ui.label("Results open automatically when processing and saving finish. Source data and quality evidence stay with this session.");
            return;
        }
        if matches!(
            self.page,
            Page::Overview | Page::Explore | Page::Investigate
        ) {
            self.reanalysis_ui(ui);
        }
        if self.session_path.is_none()
            && self.analyzer.completed_ios().is_empty()
            && self.disk_stats.is_empty()
            && self.page == Page::Overview
        {
            section_header(
                ui,
                "Connect. Start. Stop. Analyze.",
                "Automatic storage tracing for your Android phone",
            );
            ui.add_space(18.0);
            ui.label("1. Connect the phone with USB debugging enabled and approve the phone's authorization prompt.");
            ui.label("2. Select a target if more than one phone is connected, then choose Start analysis.");
            ui.label("3. Run the workload on your phone. Stop & analyze saves the session and opens the results.");
            ui.add_space(18.0);
            info_banner(
                ui,
                "Root and kernel capabilities are checked at every Start. The app prepares tracing automatically and explains FilePath confidence or unsupported metrics. No mapping file or kernel offset is required.",
            );
            if self.is_running() {
                ui.spinner();
                ui.label(&self.status);
            }
            return;
        }
        if matches!(
            self.page,
            Page::Overview | Page::Explore | Page::Investigate
        ) {
            self.filter_ui(ui);
        }
        if self.phase == CapturePhase::Error && !self.is_running() {
            self.perfetto_recovery_ui(ui);
        }
        if !self.is_running()
            && self
                .source_info
                .iter()
                .any(|r| matches!(r,WireRecord::SourceInfo{source,..} if source=="perfetto"))
        {
            ui.small("Perfetto block layer · timing matches are Probable; PID/name metadata are snapshot candidates. Missing timing stays unmeasured. FilePath is Unresolved. Device layers may count the same physical I/O more than once.");
        }
        self.rebuild_filtered();

        match self.page {
            Page::Overview => {
                if !self.analyzer.completed_ios().is_empty() {
                    self.summary_ui(ui);
                } else if self.perfetto_pending() {
                    info_banner(
                        ui,
                        "Perfetto is recording. Individual I/O counts, latency and loss statistics will be available after Stop. Device counters below are a separate live source.",
                    );
                    if !self.disk_stats.is_empty() {
                        self.diskstats_ui(ui);
                    }
                } else if self.disk_stats.is_empty() {
                    self.summary_ui(ui);
                } else {
                    self.diskstats_ui(ui);
                }
            }
            Page::Investigate => self.investigate_ui(ui),
            Page::Explore => self.explorer_ui(ui),
            Page::Compare => self.compare_ui(ui),
            Page::Diagnostics => {
                self.diagnostics_ui(ui);
                ui.collapsing("Capture source & quality evidence", |ui| {
                    for record in &self.source_info {
                        ui.label(serde_json::to_string_pretty(record).unwrap_or_default());
                    }
                });
            }
        }
        if self.page == Page::Diagnostics
            && let Some(report) = &self.preflight
        {
            ui.add_space(14.0);
            capability_panel(ui, report);
        }
    }
}
