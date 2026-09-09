// Native input regression for activity plots; enabled only by the explicit QA harness.
#[derive(Default, serde::Serialize)]
struct ActivityQa {
    #[serde(skip)]
    rect: Option<egui::Rect>,
    #[serde(skip)]
    target: Option<egui::Pos2>,
    #[serde(skip)]
    action_at: Option<Instant>,
    stable_frames: u32,
    expected_second: Option<u64>,
    origin_ns: u64,
    full_bins: usize,
    rendered_points: [usize; 2],
    visible_points: [usize; 2],
    width: f64,
    initial_width: Option<f64>,
    mean_spacing: f64,
    initial_spacing: Option<f64>,
    elapsed_ms: Option<f64>,
    plotted_series: std::collections::BTreeMap<String, Vec<[f64; 2]>>,
}

impl StudioApp {
    fn activity_qa_input(&mut self, raw: &mut egui::RawInput, gesture: &str) {
        let qa = &mut self.render_qa;
        if qa.frames < 32 || qa.frames < qa.range_wait_frame + 4 || qa.input_step >= 7 {
            return;
        }
        if qa.input_step == 0 && qa.activity.stable_frames < 8 {
            return;
        }
        if gesture == "activity-view" || gesture == "activity-throughput-view" {
            qa.input_step = 7;
            return;
        }
        if qa.input_step >= 4 {
            let done = if gesture == "activity-zoom" {
                qa.activity
                    .initial_width
                    .is_some_and(|w| qa.activity.width < w / 10.0)
                    && qa
                        .activity
                        .initial_spacing
                        .is_some_and(|s| qa.activity.mean_spacing < s)
            } else {
                self.page == Page::Explore
                    && self.selection.pending.is_none()
                    && qa
                        .activity
                        .expected_second
                        .is_some_and(|s| self.query.start_ms == s as f64 * 1000.0)
                    && self
                        .selection
                        .summary
                        .as_ref()
                        .is_some_and(|s| !s.keys.is_empty())
            };
            if done {
                qa.activity.elapsed_ms = qa
                    .activity
                    .action_at
                    .map(|t| t.elapsed().as_secs_f64() * 1000.0);
                qa.input_step = 7;
            }
            return;
        }
        let Some(pos) = qa.activity.target else {
            return;
        };
        raw.events.push(egui::Event::PointerMoved(pos));
        if qa.input_step == 0 {
            qa.activity.action_at = Some(Instant::now());
            qa.activity.initial_width = Some(qa.activity.width);
            qa.activity.initial_spacing = Some(qa.activity.mean_spacing);
        }
        if gesture == "activity-zoom" {
            if qa.input_step == 1 {
                // Exercise the plot's horizontal-only zoom modifier so the
                // constant-valued stress series remains inside the Y viewport.
                raw.events
                    .push(egui::Event::ModifiersChanged(egui::Modifiers::SHIFT));
                raw.events.push(egui::Event::Zoom(100.0));
            } else if qa.input_step == 2 {
                raw.events
                    .push(egui::Event::ModifiersChanged(egui::Modifiers::NONE));
            }
        } else if qa.input_step == 1 || qa.input_step == 3 {
            raw.events.push(egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: qa.input_step == 1,
                modifiers: Default::default(),
            });
        }
        qa.input_step += 1;
        qa.range_wait_frame = qa.frames;
    }
}
