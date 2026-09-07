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
