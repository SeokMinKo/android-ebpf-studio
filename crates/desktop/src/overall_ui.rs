#[derive(Debug, Clone, Default)]
struct OverallPoints {
    rows: Vec<(IoSelectionKey, f64, Option<f64>, f64, IoOperation)>,
}
impl OverallPoints {
    fn build(engine: &AnalysisEngine, origin: u64) -> Self {
        let rows = operation_sample_indices(engine.completed_ios(), MAX_EXPLORER_POINTS)
            .into_iter()
            .filter_map(|i| {
                let io = &engine.completed_ios()[i];
                Some((
                    selection_key(io),
                    AxisMetric::TimeMs.value(io, origin, None)?,
                    AxisMetric::IssueQueueDepth.value(io, origin, None),
                    io.issue.bytes as f64 / 1024.,
                    io.issue.operation,
                ))
            })
            .collect();
        Self { rows }
    }
}
impl StudioApp {
    fn overall_companions_ui(&mut self, ui: &mut egui::Ui) {
        let Some(view) = self.explorer_view.as_ref() else {
            return;
        };
        ui.small("Linked time axes · all panels use the current filters. Select in the LBA panel for a common request cohort; click a QD or Chunk point to inspect one request. Summary includes LBA plus paired Chunk/QD distributions.");
        let mut chosen = None;
        for (slot, axis) in [(0, AxisMetric::IssueQueueDepth), (1, AxisMetric::ChunkKiB)] {
            studio_plot(("overall-companion", slot))
                .height(170.)
                .link_axis("overall-time", [true, false])
                .link_cursor("overall-cursor", [true, false])
                .x_axis_label("Completion time (ms)")
                .y_axis_label(if slot == 0 {
                    "Observed QD at issue"
                } else {
                    axis.label()
                })
                .legend(Legend::default())
                .show(ui, |plot| {
                    for (op, label, color) in [
                        (IoOperation::Read, "Read", accent()),
                        (IoOperation::Write, "Write", green()),
                        (IoOperation::Discard, "Discard", amber()),
                        (IoOperation::Flush, "Flush", red()),
                        (IoOperation::Other, "Other", muted()),
                    ] {
                        let points: Vec<_> = view
                            .overall
                            .rows
                            .iter()
                            .filter(|r| r.4 == op)
                            .filter_map(|r| Some([r.1, if slot == 0 { r.2? } else { r.3 }]))
                            .collect();
                        plot.points(Points::new(label, points).color(color).radius(2.));
                    }
                    if plot.response().clicked()
                        && let Some(p) = plot.pointer_coordinate()
                    {
                        let mouse = plot.screen_from_plot(p);
                        chosen = view
                            .overall
                            .rows
                            .iter()
                            .filter_map(|r| {
                                let v = if slot == 0 { r.2? } else { r.3 };
                                let distance = mouse.distance(
                                    plot.screen_from_plot(egui_plot::PlotPoint::new(r.1, v)),
                                );
                                (distance < 16.).then_some((distance, r.0))
                            })
                            .min_by(|a, b| a.0.total_cmp(&b.0))
                            .map(|v| v.1);
                    }
                    if let Some(s) = self.selection.summary.as_ref() {
                        let points: Vec<_> = view
                            .overall
                            .rows
                            .iter()
                            .filter(|r| s.keys.contains(&r.0))
                            .filter_map(|r| Some([r.1, if slot == 0 { r.2? } else { r.3 }]))
                            .collect();
                        plot.points(
                            Points::new("Selected", points)
                                .filled(false)
                                .color(amber())
                                .radius(4.),
                        );
                    }
                });
        }
        if let Some(key) = chosen {
            self.begin_selection(SelectionRequest::Point(key));
        }
    }
}
