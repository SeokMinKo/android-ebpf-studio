fn explorer_numeric_grid(input: egui_plot::GridInput, spacing_factor: f64) -> Vec<egui_plot::GridMark> {
    let raw = input.base_step_size * spacing_factor;
    if !raw.is_finite() || raw <= 0.0 { return Vec::new(); }
    let power = 10f64.powf(raw.log10().floor());
    let fraction = raw / power;
    let multiplier = [1.0, 2.0, 2.5, 5.0, 10.0].into_iter().find(|v| *v >= fraction).unwrap_or(10.0);
    let step = power * multiplier;
    let first = (input.bounds.0 / step).ceil();
    (0..512).map(|i| (first + i as f64) * step)
        .take_while(|v| *v <= input.bounds.1)
        .map(|value| egui_plot::GridMark { value, step_size: step }).collect()
}

fn studio_plot(id: impl egui::AsId) -> egui_plot::Plot<'static> {
    Plot::new(id)
        .custom_x_axes(vec![
            egui_plot::AxisHints::new_x()
                .tick_label_color(ink())
                .label_spacing(64.0..=65.0),
        ])
        .custom_y_axes(vec![
            egui_plot::AxisHints::new_y()
                .tick_label_color(ink())
                .label_spacing(24.0..=25.0),
        ])
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum InspectorTab {
    #[default]
    Summary,
    Files,
    Processes,
}

fn qa_region(qa: &mut RenderQa, name: &str, rect: egui::Rect, clip: egui::Rect) {
    if qa.output.is_some() {
        qa.regions.insert(name.into(), (rect, clip));
    }
}

impl StudioApp {
    fn header_ui(&mut self, root: &mut egui::Ui, compact: bool) {
        let response = egui::Panel::top("app-header")
            .frame(
                egui::Frame::new()
                    .fill(panel())
                    .inner_margin(egui::Margin::symmetric(16, 8))
                    .stroke(Stroke::new(1.0, border())),
            )
            .show(root, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.strong(if compact {
                        "eBPF STUDIO"
                    } else {
                        "ANDROID eBPF STUDIO"
                    });
                    if compact {
                        let nav = ui.menu_button("Device / Views", |ui| {
                            ui.add_enabled_ui(!self.is_running(), |ui| {
                                egui::ComboBox::from_id_salt("compact-device")
                                    .selected_text(
                                        self.selected_serial
                                            .as_deref()
                                            .unwrap_or("Connect a phone"),
                                    )
                                    .width(180.0)
                                    .show_ui(ui, |ui| {
                                        for device in self
                                            .devices
                                            .iter()
                                            .filter(|d| d.state == DeviceState::Device)
                                        {
                                            ui.selectable_value(
                                                &mut self.selected_serial,
                                                Some(device.serial.clone()),
                                                format!(
                                                    "{} · {}",
                                                    device.model.as_deref().unwrap_or("Android"),
                                                    device.serial
                                                ),
                                            );
                                        }
                                    });
                            });
                            for page in [
                                Page::Overview,
                                Page::Explore,
                                Page::Investigate,
                                Page::Compare,
                                Page::Diagnostics,
                            ] {
                                if ui
                                    .selectable_value(&mut self.page, page, format!("{page:?}"))
                                    .clicked()
                                {
                                    ui.close();
                                }
                            }
                            ui.label("Device discovery is automatic.");
                        });
                        qa_region(
                            &mut self.render_qa,
                            "navigation",
                            nav.response.rect,
                            ui.clip_rect(),
                        );
                    }
                    status_pill(
                        ui,
                        self.phase.label(),
                        if self.phase == CapturePhase::Error {
                            red()
                        } else {
                            accent()
                        },
                    );
                    let running = self.is_running();
                    let action = if running {
                        ui.add_enabled(
                            matches!(
                                self.phase,
                                CapturePhase::Preparing | CapturePhase::Recording
                            ),
                            egui::Button::new(
                                RichText::new("Stop & analyze").color(Color32::BLACK),
                            )
                            .fill(amber()),
                        )
                    } else {
                        ui.add_enabled(
                            self.selected_serial.is_some(),
                            egui::Button::new(RichText::new("Start analysis").color(
                                ACTIVE_THEME.with(|v| {
                                    if v.get() == ThemeChoice::Light {
                                        Color32::WHITE
                                    } else {
                                        Color32::BLACK
                                    }
                                }),
                            ))
                            .fill(accent()),
                        )
                    };
                    qa_region(
                        &mut self.render_qa,
                        "capture-action",
                        action.rect,
                        ui.clip_rect(),
                    );
                    if action.clicked() {
                        if running {
                            self.stop();
                        } else {
                            self.start_device();
                        }
                    }
                    let open = ui.add_enabled(!running, egui::Button::new("Open session"));
                    qa_region(&mut self.render_qa, "open-session", open.rect, ui.clip_rect());
                    if open.clicked() {
                        self.open_session();
                    }
                    let session = ui.menu_button("Session", |ui| {
                        ui.add_enabled_ui(!self.is_running(), |ui| {
                            if ui.button("Open session").clicked() {
                                ui.close();
                                self.open_session();
                            }
                            let raw = self
                                .session_path
                                .as_deref()
                                .and_then(crate::perfetto_session::raw_trace_path)
                                .is_some();
                            let recovery = self
                                .session_path
                                .as_deref()
                                .and_then(crate::perfetto_session::recovery_manifest)
                                .is_some();
                            let export_raw = ui.add_enabled(
                                raw && !self.raw_export_pending,
                                egui::Button::new("Export Perfetto raw trace"),
                            );
                            self.render_qa.inspector_buttons.insert(
                                "Export Perfetto raw trace".into(),
                                export_raw.rect.center(),
                            );
                            if export_raw.clicked() {
                                ui.close();
                                self.export_perfetto_raw();
                            }
                            if ui
                                .add_enabled(raw, egui::Button::new("Reanalyze saved raw trace"))
                                .clicked()
                            {
                                ui.close();
                                self.recover_perfetto(false);
                            }
                            if ui
                                .add_enabled(
                                    recovery,
                                    egui::Button::new("Recover from original phone"),
                                )
                                .clicked()
                            {
                                ui.close();
                                self.recover_perfetto(true);
                            }
                            if ui
                                .add_enabled(
                                    self.session_path.is_some(),
                                    egui::Button::new("Export CSV"),
                                )
                                .clicked()
                            {
                                ui.close();
                                self.export_csv();
                            }
                            if ui
                                .add_enabled(
                                    !self.analysis().completed_ios().is_empty(),
                                    egui::Button::new("Export view"),
                                )
                                .clicked()
                            {
                                ui.close();
                                self.export_analysis_view();
                            }
                        });
                    });
                    qa_region(
                        &mut self.render_qa,
                        "session-menu",
                        session.response.rect,
                        ui.clip_rect(),
                    );
                    self.render_qa.session_button = Some(session.response.rect.center());
                    let theme = egui::ComboBox::from_id_salt("theme")
                        .width(112.0)
                        .selected_text(match self.theme {
                            ThemeChoice::HighContrast => "High Contrast".into(),
                            v => format!("{v:?}"),
                        })
                        .show_ui(ui, |ui| {
                            for theme in [
                                ThemeChoice::System,
                                ThemeChoice::Light,
                                ThemeChoice::Dark,
                                ThemeChoice::HighContrast,
                            ] {
                                ui.selectable_value(
                                    &mut self.theme,
                                    theme,
                                    if theme == ThemeChoice::HighContrast {
                                        "High Contrast".into()
                                    } else {
                                        format!("{theme:?}")
                                    },
                                );
                            }
                        });
                    qa_region(
                        &mut self.render_qa,
                        "theme",
                        theme.response.rect,
                        ui.clip_rect(),
                    );
                });
                if !self.is_running() && self.selected_serial.is_none() {
                    ui.label("To record: connect and authorize an Android phone. To review an existing capture: Open session.");
                }
                ui.horizontal_wrapped(|ui| {
                    if let Some(start) = self.started_at
                        && self.is_running()
                    {
                        ui.label(format!(
                            "{} s · {} events",
                            start.elapsed().as_secs(),
                            self.received_events
                        ));
                    }
                    ui.label(RichText::new(&self.status).color(
                        if self.phase == CapturePhase::Error {
                            red()
                        } else {
                            ink()
                        },
                    ));
                    if self.is_running() || self.received_events > 0 {
                        ui.label(RichText::new(&self.loss_status).color(muted()));
                    }
                });
            });
        qa_region(
            &mut self.render_qa,
            "header",
            response.response.rect,
            root.clip_rect(),
        );
    }
}

#[cfg(test)]
mod ui_layout_tests {
    use super::*;


    #[test]
    fn wide_time_axis_labels_do_not_overlap() {
        let ctx = egui::Context::default();
        apply_theme(&ctx, ThemeChoice::Light);
        let render = || ctx.run_ui(egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(2400.0, 300.0))),
            ..Default::default()
        }, |root| { egui::CentralPanel::default().show(root, |ui| {
            studio_plot("wide-time-labels").height(220.0).show(ui, |plot| {
                plot.points(Points::new("Read", vec![[0.0, 45615.0], [7500.0, 45624.0]]));
            });
        }); });
        let mut first = render(); first.textures_delta.clear();
        let mut output = render(); output.textures_delta.clear();
        fn collect(shape: &egui::Shape, labels: &mut Vec<egui::Rect>) {
            match shape {
                egui::Shape::Text(t) if t.galley.job.text.parse::<f64>().is_ok() => labels.push(egui::Rect::from_min_size(t.pos, t.galley.size())),
                egui::Shape::Vec(shapes) => for s in shapes { collect(s, labels); },
                _ => {}
            }
        }
        let mut labels = Vec::new();
        for s in output.shapes { collect(&s.shape, &mut labels); }
        let bottom = labels.iter().map(|r|r.min.y).fold(f32::NEG_INFINITY, f32::max);
        labels.retain(|r| (r.min.y-bottom).abs()<1.0);
        labels.sort_by(|a,b| a.min.x.total_cmp(&b.min.x));
        assert!(labels.len()>=3, "Need visible time ticks");
        for pair in labels.windows(2) { assert!(pair[0].max.x+4.0 <= pair[1].min.x, "Overlapping time labels: {:?}",pair); }
    }

    #[test]
    fn high_contrast_numeric_tick_text_does_not_fade_with_grid_strength() {
        let ctx = egui::Context::default();
        apply_theme(&ctx, ThemeChoice::HighContrast);
        let render = || {
            ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(800.0, 500.0),
                    )),
                    ..Default::default()
                },
                |root| {
                    egui::CentralPanel::default().show(root, |ui| {
                        studio_plot("contrast-regression")
                            .height(220.0)
                            .show(ui, |plot| {
                                plot.points(Points::new(
                                    "",
                                    vec![[0.0, 0.0], [7500.0, 84_000_000.0]],
                                ));
                            });
                    });
                },
            )
        };
        let mut first = render();
        first.textures_delta.clear();
        let mut output = render();
        output.textures_delta.clear();
        let mut count = 0;
        fn check(shape: &egui::Shape, count: &mut usize) {
            match shape {
                egui::Shape::Text(t) if t.galley.job.text.parse::<f64>().is_ok() => {
                    *count += 1;
                    assert_eq!(
                        t.fallback_color,
                        Color32::WHITE,
                        "Tick {} is faded",
                        t.galley.job.text
                    );
                }
                egui::Shape::Vec(shapes) => {
                    for s in shapes {
                        check(s, count)
                    }
                }
                _ => {}
            }
        }
        for s in output.shapes {
            check(&s.shape, &mut count);
        }
        assert!(count >= 3, "Need real painted numeric ticks, got {count}");
    }
}

fn activity_plot(id: impl egui::AsId) -> egui_plot::Plot<'static> {
    studio_plot(id).y_grid_spacer(|input| {
        let span = input.bounds.1 - input.bounds.0;
        if !span.is_finite() || span <= 0. {
            return Vec::new();
        }
        // Four intervals keep numeric ticks readable in the short activity panels.
        let raw = span / 4.;
        let power = 10_f64.powf(raw.log10().floor());
        let fraction = raw / power;
        let step = power
            * if fraction <= 1. {
                1.
            } else if fraction <= 2. {
                2.
            } else if fraction <= 5. {
                5.
            } else {
                10.
            };
        if !step.is_finite() || step <= 0. {
            return Vec::new();
        }
        let first = (input.bounds.0 / step).ceil() * step;
        (0..6)
            .map(|i| first + i as f64 * step)
            .take_while(|value| *value <= input.bounds.1)
            .map(|value| egui_plot::GridMark {
                value,
                step_size: step,
            })
            .collect()
    })
}

#[cfg(test)]
mod activity_axis_tests {
    use super::*;
    #[test]
    fn short_iops_plot_has_readable_nonzero_ticks() {
        let ctx = egui::Context::default();
        let mut labels = Vec::new();
        fn texts(shape: &egui::Shape, out: &mut Vec<String>) {
            match shape {
                egui::Shape::Text(t) => out.push(t.galley.text().to_owned()),
                egui::Shape::Vec(v) => {
                    for s in v {
                        texts(s, out);
                    }
                }
                _ => {}
            }
        }
        for _ in 0..8 {
            let mut output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1200., 250.),
                    )),
                    ..Default::default()
                },
                |root| {
                    egui::CentralPanel::default().show(root, |ui| {
                        activity_plot("regression-iops")
                            .height(170.)
                            .show_axes([false, true])
                            .include_y(0.)
                            .include_y(65.)
                            .show(ui, |plot| {
                                plot.points(Points::new(
                                    "Read",
                                    vec![[0.5, 11.], [1.5, 55.], [4.5, 65.]],
                                ));
                            });
                    });
                },
            );
            labels.clear();
            for shape in &output.shapes {
                texts(&shape.shape, &mut labels);
            }
            output.textures_delta.clear();
        }
        let nonzero: Vec<_> = labels
            .iter()
            .filter_map(|s| s.parse::<f64>().ok())
            .filter(|v| *v > 0. && *v <= 65.)
            .collect();
        assert!(
            nonzero.len() >= 2,
            "Y axis must expose at least two nonzero tick labels, got {labels:?}"
        );
    }
}

