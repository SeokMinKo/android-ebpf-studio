// View bounds are session-local and do not alter the analysis cohort.
#[derive(Default)]
struct AxisRangeEditor {
    values: [[String; 2]; 2],
    initialized: bool,
    error: Option<String>,
}

impl AxisRangeEditor {
    fn read_view(&mut self, bounds: egui_plot::PlotBounds) {
        for axis in 0..2 {
            self.values[axis] = [
                bounds.min()[axis].to_string(),
                bounds.max()[axis].to_string(),
            ];
        }
        self.initialized = true;
        self.error = None;
    }

    fn parse(
        &self,
        current: egui_plot::PlotBounds,
        axes: [bool; 2],
    ) -> Result<egui_plot::PlotBounds, String> {
        let (mut min, mut max) = (current.min(), current.max());
        for axis in 0..2 {
            if !axes[axis] {
                continue;
            }
            let name = ["X", "Y"][axis];
            let low = self.values[axis][0]
                .trim()
                .parse::<f64>()
                .map_err(|_| format!("{name} Min must be a number."))?;
            let high = self.values[axis][1]
                .trim()
                .parse::<f64>()
                .map_err(|_| format!("{name} Max must be a number."))?;
            if !low.is_finite() || !high.is_finite() || !(high - low).is_finite() || low >= high {
                return Err(format!("{name}: use finite values with Min < Max."));
            }
            min[axis] = low;
            max[axis] = high;
        }
        Ok(egui_plot::PlotBounds::from_min_max(min, max))
    }
}

impl SelectionState {
    fn remember_view(&mut self) {
        if let Some(bounds) = self.current_bounds {
            if self.zoom_history.len() == 32 {
                self.zoom_history.remove(0);
            }
            self.zoom_history.push(bounds);
        }
    }

    fn apply_axis_range(&mut self, axes: [bool; 2]) {
        let Some(current) = self.current_bounds else {
            return;
        };
        match self.axis_range.parse(current, axes) {
            Ok(bounds) => {
                self.remember_view();
                self.auto_bounds = false;
                self.bounds_command = Some(bounds);
                self.axis_range.error = None;
            }
            Err(error) => self.axis_range.error = Some(error),
        }
    }

    fn fit_axis_ranges(&mut self) {
        self.remember_view();
        self.bounds_command = None;
        self.auto_bounds = true;
        self.axis_range = AxisRangeEditor::default();
    }
}

impl StudioApp {
    fn axis_ranges_ui(&mut self, ui: &mut egui::Ui) {
        egui::CollapsingHeader::new("Axis ranges · X / Y Min–Max")
            .open(
                (self.render_qa.output.is_some()
                    && std::env::var_os("ANDROID_EBPF_QA_RANGE").is_some())
                .then_some(true),
            )
            .show(ui, |ui| {
                if !self.selection.axis_range.initialized
                    && let Some(bounds) = self.selection.current_bounds
                {
                    self.selection.axis_range.read_view(bounds);
                }
                for (axis, metric) in [(0, self.x_axis), (1, self.y_axis)] {
                    ui.horizontal_wrapped(|ui| {
                        ui.strong(format!("{} · {}", ["X", "Y"][axis], metric.label()));
                        for edge in 0..2 {
                            let label = ui.label(["Min", "Max"][edge]);
                            ui.add(
                                egui::TextEdit::singleline(
                                    &mut self.selection.axis_range.values[axis][edge],
                                )
                                .id_salt(("axis-range", axis, edge))
                                .desired_width(128.0),
                            )
                            .labelled_by(label.id);
                        }
                        if ui
                            .add_enabled(
                                self.selection.current_bounds.is_some(),
                                egui::Button::new(format!("Apply {}", ["X", "Y"][axis])),
                            )
                            .clicked()
                        {
                            self.selection.apply_axis_range([axis == 0, axis == 1]);
                        }
                    });
                }
                ui.horizontal_wrapped(|ui| {
                    let apply = ui.add_enabled(
                        self.selection.current_bounds.is_some(),
                        egui::Button::new("Apply X + Y"),
                    );
                    self.render_qa.range_apply_button = Some(apply.rect.center());
                    if self.render_qa.output.is_some()
                        && self.render_qa.input_step == 0
                        && std::env::var_os("ANDROID_EBPF_QA_SMALL").is_some()
                        && !ui.clip_rect().contains_rect(apply.rect)
                    {
                        ui.scroll_to_rect(apply.rect, Some(egui::Align::Center));
                    }
                    if apply.clicked() {
                        self.selection.apply_axis_range([true, true]);
                        self.render_qa.range_actions += 1;
                    }
                    if ui.button("Use current view").clicked()
                        && let Some(bounds) = self.selection.current_bounds
                    {
                        self.selection.axis_range.read_view(bounds);
                    }
                    let auto = ui.button("Auto range");
                    self.render_qa.range_auto_button = Some(auto.rect.center());
                    if auto.clicked() {
                        self.selection.fit_axis_ranges();
                    }
                    ui.label("View only · Back restores the previous range");
                });
                if let Some(error) = &self.selection.axis_range.error {
                    ui.colored_label(red(), format!("Invalid range: {error}"));
                }
            });
    }
}

#[cfg(test)]
mod axis_range_tests {
    use super::*;
    fn bounds() -> egui_plot::PlotBounds {
        egui_plot::PlotBounds::from_min_max([1.0, 10.0], [5.0, 50.0])
    }

    #[test]
    fn single_axis_preserves_other_axis_and_accepts_scientific_notation() {
        let mut editor = AxisRangeEditor::default();
        editor.read_view(bounds());
        editor.values[0] = [" -2e1 ".into(), "2e2".into()];
        editor.values[1] = ["invalid unused draft".into(), "".into()];
        let result = editor.parse(bounds(), [true, false]).unwrap();
        assert_eq!(result.min(), [-20.0, 10.0]);
        assert_eq!(result.max(), [200.0, 50.0]);
    }

    #[test]
    fn invalid_ranges_do_not_mutate_view_or_history() {
        for (low, high) in [
            ("NaN", "2"),
            ("1", "inf"),
            ("2", "2"),
            ("3", "2"),
            ("-1e308", "1e308"),
            ("", "2"),
        ] {
            let mut state = SelectionState {
                current_bounds: Some(bounds()),
                ..Default::default()
            };
            state.axis_range.read_view(bounds());
            state.axis_range.values[0] = [low.into(), high.into()];
            state.apply_axis_range([true, true]);
            assert!(state.axis_range.error.is_some(), "{low} {high}");
            assert!(state.bounds_command.is_none());
            assert!(state.zoom_history.is_empty());
        }
    }

    #[test]
    fn manual_and_auto_ranges_share_bounded_history_and_keep_selection() {
        let mut state = SelectionState {
            current_bounds: Some(bounds()),
            summary: Some(SelectionSummary::default()),
            ..Default::default()
        };
        state.axis_range.read_view(bounds());
        state.axis_range.values[1] = ["20".into(), "30".into()];
        state.apply_axis_range([false, true]);
        assert_eq!(state.bounds_command.unwrap().min(), [1.0, 20.0]);
        assert_eq!(state.zoom_history.pop().unwrap(), bounds());
        state.fit_axis_ranges();
        assert!(state.auto_bounds && state.bounds_command.is_none());
        assert!(state.summary.is_some());
        for _ in 0..50 {
            state.remember_view();
        }
        assert_eq!(state.zoom_history.len(), 32);
    }
}
