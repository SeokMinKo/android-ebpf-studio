#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
struct LatencyRange {
    min_ns: u64,
    max_exclusive_ns: Option<u64>,
}

#[cfg(test)]
mod latency_drilldown_tests {
    use super::*;
    use android_ebpf_protocol::{BlockComplete, BlockIssue, StorageEvent};

    fn fixture() -> StudioApp {
        let mut app = StudioApp::default();
        for (i, latency) in [0, 1, 2, 3, 4, 7, 8, 15, 16, 31].into_iter().enumerate() {
            let id = i as u64 + 1;
            app.analyzer.ingest(StorageEvent::BlockIssue(BlockIssue {
                ts_ns: id * 1_000_000,
                request_id: id,
                device_major: 8,
                device_minor: 0,
                sector: id * 8,
                sectors: 8,
                bytes: 4096,
                operation: if i % 2 == 0 {
                    IoOperation::Read
                } else {
                    IoOperation::Write
                },
                pid: 42,
                tid: 43,
                cpu: 0,
                comm: "worker".into(),
            }));
            app.analyzer
                .ingest(StorageEvent::BlockComplete(BlockComplete {
                    ts_ns: id * 1_000_000 + latency,
                    request_id: id,
                    device_major: 8,
                    device_minor: 0,
                    status: 0,
                }));
        }
        app
    }

    #[test]
    fn bucket_edges_are_exact_and_do_not_turn_unknown_latency_into_zero() {
        for bucket in 0..=63 {
            let range = LatencyRange::from_buckets(bucket, bucket).unwrap();
            assert!(!range.contains(None));
            assert!(range.contains(Some(range.min_ns)));
            if range.min_ns > 0 {
                assert!(!range.contains(Some(range.min_ns - 1)));
            }
            if let Some(end) = range.max_exclusive_ns {
                assert!(range.contains(Some(end - 1)));
                assert!(!range.contains(Some(end)));
                assert_eq!(latency_bucket(end - 1), bucket);
            } else {
                assert!(range.contains(Some(u64::MAX)));
            }
        }
        assert!(LatencyRange::from_buckets(0, 0).unwrap().contains(Some(0)));
        assert!(LatencyRange::from_buckets(8, 7).is_none());
        assert!(LatencyRange::from_buckets(63, 64).is_none());
    }

    #[test]
    fn drag_selects_intersecting_bins_in_both_directions_and_ignores_empty_space() {
        let bins = BTreeMap::from([(4, 2), (7, 3), (8, 1)]);
        assert_eq!(
            latency_drag_range(&bins, 3.7, 7.2),
            LatencyRange::from_buckets(4, 7)
        );
        assert_eq!(
            latency_drag_range(&bins, 7.2, 3.7),
            LatencyRange::from_buckets(4, 7)
        );
        assert_eq!(latency_drag_range(&bins, 5.0, 6.0), None);
        assert_eq!(latency_drag_range(&bins, f64::NAN, 8.0), None);
    }

    #[test]
    fn drilldown_preserves_other_filters_and_links_summary_to_the_exact_requests() {
        let mut app = fixture();
        app.query.operation = Some(IoOperation::Write);
        app.query.pid = 42;
        app.query.device = "8:0".into();
        app.query.start_ms = 3.0;
        app.explore_latency_range(LatencyRange::from_buckets(1, 3).unwrap());
        let deadline = Instant::now() + Duration::from_secs(3);
        while app.selection.pending.is_some() {
            app.poll_selection();
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert_eq!(app.page, Page::Explore);
        assert_eq!(app.query.operation, Some(IoOperation::Write));
        assert_eq!(app.query.pid, 42);
        assert_eq!(app.query.start_ms, 3.0);
        let ids: Vec<_> = app
            .analysis()
            .completed_ios()
            .iter()
            .map(|io| io.issue.request_id)
            .collect();
        assert_eq!(ids, vec![4, 6, 8]);
        let summary = app.selection.summary.as_ref().unwrap();
        assert_eq!(summary.keys.len(), 3);
        assert_eq!(summary.write.bytes, 3 * 4096);
        assert_eq!(summary.write.percentile(50), Some(7));
        assert_eq!(summary.write.percentile(100), Some(15));
        assert_eq!(summary.processes.len(), 1);
        assert_eq!(summary.files.values().next().unwrap().count, 3);
        assert_eq!(app.analysis_summary().completed_ios, 3);
        let exported = serde_json::to_value(&app.query).unwrap();
        assert_eq!(exported["latency_range"]["min_ns"], 2);
        assert_eq!(exported["latency_range"]["max_exclusive_ns"], 16);
        app.query.latency_range = None;
        app.invalidate_query();
        app.rebuild_filtered();
        assert_eq!(app.analysis().completed_ios().len(), 4);
        assert_eq!(app.analyzer.completed_ios().len(), 10);
    }
}

fn latency_bucket(ns: u64) -> u32 {
    63 - ns.max(1).leading_zeros()
}

impl LatencyRange {
    fn from_buckets(first: u32, last: u32) -> Option<Self> {
        if first > last || last > 63 {
            return None;
        }
        Some(Self {
            min_ns: if first == 0 { 0 } else { 1_u64 << first },
            max_exclusive_ns: 1_u64.checked_shl(last + 1),
        })
    }
    fn contains(self, latency: Option<u64>) -> bool {
        latency
            .is_some_and(|ns| ns >= self.min_ns && self.max_exclusive_ns.is_none_or(|end| ns < end))
    }
    fn label(self) -> String {
        self.max_exclusive_ns.map_or_else(
            || format!("≥ {} ns", self.min_ns),
            |end| format!("[{}, {}) ns", self.min_ns, end),
        )
    }
}

// Coordinates select histogram bins, never the aggregate count on the Y axis.
fn latency_drag_range(
    histogram: &BTreeMap<u32, u64>,
    start: f64,
    end: f64,
) -> Option<LatencyRange> {
    if !start.is_finite() || !end.is_finite() {
        return None;
    }
    let low = start.min(end);
    let high = start.max(end);
    let mut bins = histogram
        .keys()
        .copied()
        .filter(|b| *b as f64 + 0.4 >= low && *b as f64 - 0.4 <= high);
    let first = bins.next()?;
    LatencyRange::from_buckets(first, bins.next_back().unwrap_or(first))
}

impl StudioApp {
    fn explore_latency_range(&mut self, range: LatencyRange) {
        self.query.latency_range = Some(range);
        self.invalidate_query();
        self.rebuild_filtered();
        self.explorer_preset = ExplorerPreset::LatencyTimeline;
        self.x_axis = AxisMetric::TimeMs;
        self.y_axis = AxisMetric::TotalLatencyMs;
        self.group_by = GroupBy::Direction;
        self.selection.enabled = true;
        self.page = Page::Explore;
        self.begin_selection(all_plot_requests());
    }

    fn latency_distribution_ui(
        &mut self,
        ui: &mut egui::Ui,
        histogram: &BTreeMap<u32, u64>,
        total: u64,
    ) -> Option<LatencyRange> {
        ui.strong("Total latency distribution");
        let measured: u64 = histogram.values().sum();
        ui.label(format!(
            "{measured} measured / {total} I/O · {} have no valid latency",
            total.saturating_sub(measured)
        ));
        if histogram.is_empty() {
            ui.label("Latency distribution unavailable. Unmeasured I/O remain in counts, volume and address views.");
            return None;
        }
        ui.small("Click a bin column or drag horizontally across bins to explore those I/O. Other filters stay active. Bin 0 includes 0–1 ns; other bins are [2^x, 2^(x+1)) ns.");
        let id = ui.make_persistent_id(("latency-drag", self.analysis_generation));
        let mut drag = ui.ctx().data_mut(|d| d.get_temp::<f64>(id));
        let mut selected = None;
        let qa_gesture = self
            .render_qa
            .output
            .as_ref()
            .and_then(|_| std::env::var("ANDROID_EBPF_QA_GESTURE").ok());
        let qa_active = qa_gesture
            .as_ref()
            .is_some_and(|g| g.starts_with("latency-"));
        let qa_keyboard = qa_gesture.as_deref() == Some("latency-keyboard");
        if qa_active
            && !qa_keyboard
            && self.render_qa.frames >= 28
            && self.render_qa.input_step == 0
        {
            ui.scroll_to_rect(
                egui::Rect::from_min_size(ui.cursor().min, egui::vec2(ui.available_width(), 180.0)),
                Some(egui::Align::Center),
            );
        }
        let clip = ui.clip_rect();
        studio_plot("latency-distribution")
            .height(180.0)
            .allow_drag(false)
            .allow_boxed_zoom(false)
            .x_axis_label("Latency bucket (log2 nanoseconds)")
            .y_axis_label("I/O count")
            .show(ui, |plot| {
                if qa_active {
                    let rect = plot.response().rect;
                    if self.render_qa.latency_stable_rect == Some(rect) {
                        self.render_qa.latency_stable_frames += 1;
                    } else {
                        self.render_qa.latency_stable_rect = Some(rect);
                        self.render_qa.latency_stable_frames = 0;
                    }
                    self.render_qa.latency_targets = histogram
                        .iter()
                        .filter_map(|(&bucket, &count)| {
                            let point = plot.screen_from_plot(egui_plot::PlotPoint::new(
                                bucket as f64,
                                (count as f64 * 0.5).max(5.0),
                            ));
                            clip.contains(point).then_some((bucket, point))
                        })
                        .collect();
                }
                let bars = histogram
                    .iter()
                    .map(|(bucket, count)| {
                        egui_plot::Bar::new(*bucket as f64, *count as f64)
                            .width(0.8)
                            .name(format!(
                                "{} · {count} I/O",
                                LatencyRange::from_buckets(*bucket, *bucket)
                                    .unwrap()
                                    .label()
                            ))
                    })
                    .collect();
                plot.bar_chart(
                    egui_plot::BarChart::new("Measured total latency", bars).color(amber()),
                );
                if plot.response().clicked()
                    && let Some(p) = plot.pointer_coordinate()
                    && let Some((&bucket, _)) = histogram
                        .iter()
                        .find(|(b, _)| (p.x - **b as f64).abs() <= 0.4)
                {
                    selected = LatencyRange::from_buckets(bucket, bucket);
                }
                if plot.response().drag_started()
                    && let Some(pos) = plot.response().interact_pointer_pos()
                {
                    drag = Some(plot.plot_from_screen(pos - plot.response().drag_delta()).x);
                }
                if let Some(start) = drag
                    && let Some(p) = plot.pointer_coordinate()
                {
                    let bound = plot.plot_bounds();
                    plot.polygon(
                        egui_plot::Polygon::new(
                            "Selected latency bins",
                            vec![
                                [start, bound.min()[1]],
                                [p.x, bound.min()[1]],
                                [p.x, bound.max()[1]],
                                [start, bound.max()[1]],
                            ],
                        )
                        .fill_color(amber().gamma_multiply(0.15)),
                    );
                    if plot.response().drag_stopped() {
                        selected = latency_drag_range(histogram, start, p.x);
                        drag = None;
                    }
                }
                if plot.response().drag_stopped() {
                    drag = None;
                }
            });
        ui.ctx().data_mut(|d| {
            if let Some(start) = drag {
                d.insert_temp(id, start);
            } else {
                d.remove::<f64>(id);
            }
        });
        if qa_keyboard && self.render_qa.frames >= 28 && self.render_qa.input_step == 0 {
            ui.scroll_to_rect(
                egui::Rect::from_min_size(ui.cursor().min, egui::vec2(ui.available_width(), 220.0)),
                Some(egui::Align::Center),
            );
        }
        egui::CollapsingHeader::new("Latency bins · keyboard and table access")
            .open(qa_keyboard.then_some(true))
            .show(ui, |ui| {
                let range_id =
                    ui.make_persistent_id(("latency-keyboard-range", self.analysis_generation));
                let first = *histogram.first_key_value().unwrap().0;
                let last = *histogram.last_key_value().unwrap().0;
                let mut range = ui
                    .ctx()
                    .data_mut(|d| d.get_temp::<[u32; 2]>(range_id))
                    .unwrap_or([first, last]);
                ui.horizontal_wrapped(|ui| {
                    for (index, label) in ["From bin", "Through bin"].into_iter().enumerate() {
                        egui::ComboBox::from_id_salt(("latency-range", index))
                            .selected_text(format!("{label} {}", range[index]))
                            .show_ui(ui, |ui| {
                                for &bucket in histogram.keys() {
                                    ui.selectable_value(
                                        &mut range[index],
                                        bucket,
                                        format!("Bin {bucket}"),
                                    );
                                }
                            });
                    }
                    let selected_range = LatencyRange::from_buckets(range[0], range[1]);
                    if ui
                        .add_enabled(
                            selected_range.is_some(),
                            egui::Button::new("Explore selected bins"),
                        )
                        .clicked()
                    {
                        selected = selected_range;
                    }
                });
                ui.ctx().data_mut(|d| d.insert_temp(range_id, range));
                egui::ScrollArea::vertical()
                    .id_salt("latency-bins-table")
                    .max_height(220.0)
                    .show(ui, |ui| {
                        for (&bucket, &count) in histogram {
                            let range = LatencyRange::from_buckets(bucket, bucket).unwrap();
                            let response =
                                ui.button(format!("Explore {} · {count} I/O", range.label()));
                            if qa_keyboard
                                && bucket == first
                                && self.render_qa.frames >= 28
                                && self.render_qa.input_step == 0
                            {
                                response.scroll_to_me(Some(egui::Align::Center));
                                response.request_focus();
                                self.render_qa.latency_table_target = ui
                                    .clip_rect()
                                    .contains(response.rect.center())
                                    .then_some(response.rect.center());
                                self.render_qa.latency_expected = Some(range);
                            }
                            if response.clicked() {
                                selected = Some(range);
                            }
                        }
                    });
            });
        selected
    }
}

impl StudioApp {
    fn latency_qa_input(&mut self, raw: &mut egui::RawInput, gesture: &str) {
        if self.render_qa.frames < 32 || self.render_qa.frames < self.render_qa.range_wait_frame + 4
        {
            return;
        }
        let step = self.render_qa.input_step;
        if step == 0 && self.render_qa.latency_stable_frames < 8 {
            return;
        }
        if step >= 7 {
            return;
        }
        if step >= 4 {
            if self.page == Page::Explore
                && self.selection.pending.is_none()
                && self.query.latency_range == self.render_qa.latency_expected
                && self
                    .selection
                    .summary
                    .as_ref()
                    .is_some_and(|s| !s.keys.is_empty())
            {
                self.render_qa.input_step = 7;
                self.render_qa.latency_elapsed_ms = self
                    .render_qa
                    .latency_action_at
                    .map(|t| t.elapsed().as_secs_f64() * 1000.0);
            }
            return;
        }
        if gesture == "latency-keyboard" {
            if self.render_qa.latency_table_target.is_none() {
                return;
            }
            if step == 1 || step == 2 {
                raw.events.push(egui::Event::Key {
                    key: egui::Key::Enter,
                    physical_key: Some(egui::Key::Enter),
                    pressed: step == 1,
                    repeat: false,
                    modifiers: Default::default(),
                });
            }
        } else {
            let Some(&(first, start)) = self.render_qa.latency_targets.first() else {
                return;
            };
            if gesture == "latency-view" {
                self.render_qa.input_step = 7;
                return;
            }
            let (last, end) = if gesture == "latency-area" {
                self.render_qa
                    .latency_targets
                    .get(1)
                    .copied()
                    .unwrap_or((first, start))
            } else {
                (first, start)
            };
            self.render_qa.latency_expected = LatencyRange::from_buckets(first, last);
            let pos = if step >= 2 { end } else { start };
            raw.events.push(egui::Event::PointerMoved(pos));
            if step == 1 || step == 3 {
                raw.events.push(egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: step == 1,
                    modifiers: Default::default(),
                });
            }
        }
        if step == 0 {
            self.render_qa.latency_action_at = Some(Instant::now());
        }
        self.render_qa.input_step += 1;
        self.render_qa.range_wait_frame = self.render_qa.frames;
    }
}
