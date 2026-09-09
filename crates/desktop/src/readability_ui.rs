// Presentation-only helpers. Query matching and measurement semantics remain
// owned by AnalysisFilter and the protocol analysis engine.
impl AnalysisFilter {
    fn scope_description(&self) -> String {
        let mut parts = Vec::new();
        if !self.file.is_empty() {
            parts.push(format!("Path {}: {}", if self.file_exact { "equals" } else { "contains" }, self.file));
        } else if self.file_exact {
            parts.push("Full-path matching enabled".into());
        }
        if self.start_ms > 0.0 || self.end_ms > 0.0 {
            let end = if self.end_ms > 0.0 { format!("{} ms", self.end_ms) } else { "session end".into() };
            parts.push(format!("Time: {} ms to {end}", self.start_ms));
        }
        if self.pid != 0 { parts.push(format!("PID {}", self.pid)); }
        if self.tid != 0 { parts.push(format!("TID {}", self.tid)); }
        if !self.process.is_empty() { parts.push(format!("Process: {}", self.process)); }
        if !self.device.is_empty() { parts.push(format!("Device: {}", self.device)); }
        if let Some(op) = self.operation { parts.push(operation_label(op).into()); }
        if let Some(confidence) = self.confidence { parts.push(format!("Path confidence: {confidence:?}")); }
        if self.min_bytes > 0 || self.max_bytes > 0 {
            let max = if self.max_bytes > 0 { self.max_bytes.to_string() } else { "unlimited".into() };
            parts.push(format!("Bytes: {} to {max}", self.min_bytes));
        }
        if let Some(access) = self.access { parts.push(format!("Access: {access:?}")); }
        if let Some(cpu) = self.cpu { parts.push(format!("CPU {cpu}")); }
        if let Some(layer) = self.layer { parts.push(format!("Layer: {layer:?}")); }
        if let Some(range) = self.latency_range { parts.push(format!("Total latency: {}", range.label())); }
        if let Some(keys) = &self.request_keys { parts.push(format!("{} selected request identities", keys.len())); }
        if parts.is_empty() { "All loaded requests".into() } else { parts.join(" · ") }
    }
}

// A single column contract aligns the fixed header and virtualized body.
const IO_TABLE_COLUMNS: [(&str, f32, bool); 14] = [
    ("Details", 85.0, false),
    ("Time ns", 155.0, true),
    ("Op", 65.0, false),
    ("Access", 100.0, false),
    ("Bytes", 90.0, true),
    ("Sector", 120.0, true),
    ("Device", 85.0, false),
    ("Queue latency", 110.0, true),
    ("Device latency", 115.0, true),
    ("Total latency", 115.0, true),
    ("File / Origin", 280.0, false),
    ("Confidence", 100.0, false),
    ("PID / TID", 130.0, false),
    ("Process", 150.0, false),
];

fn io_table_cell(ui: &mut egui::Ui, column: usize, text: &str, heading: bool) -> egui::Response {
    let (_, width, numeric) = IO_TABLE_COLUMNS[column];
    let layout = if numeric {
        egui::Layout::right_to_left(egui::Align::Center)
    } else {
        egui::Layout::left_to_right(egui::Align::Center)
    };
    ui.allocate_ui_with_layout(egui::vec2(width, 28.0), layout, |ui| {
        ui.set_width(width);
        ui.set_min_height(28.0);
        let value = if heading {
            RichText::new(text).strong()
        } else if numeric || column == 6 || column == 12 {
            RichText::new(text).monospace()
        } else {
            RichText::new(text)
        };
        ui.add(egui::Label::new(value).truncate()).on_hover_text(text)
    }).inner
}

#[cfg(test)]
mod readability_tests {
    use super::*;

    #[test]
    fn scope_names_hidden_constraints_and_cpu_zero() {
        let query = AnalysisFilter {
            pid: 42, cpu: Some(0), operation: Some(IoOperation::Read),
            request_keys: Some(Default::default()), end_ms: 12.5,
            ..Default::default()
        };
        let summary = query.scope_description();
        for expected in ["PID 42", "CPU 0", "Read", "0 selected request identities", "12.5 ms"] {
            assert!(summary.contains(expected), "{expected} missing from {summary}");
        }
        assert_eq!(AnalysisFilter::default().scope_description(), "All loaded requests");
    }

    #[test]
    fn path_scope_preserves_full_unicode_and_matching_mode() {
        let query = AnalysisFilter {
            file: "/data/긴 파일 이름/trace.bin".into(), file_exact: true,
            ..Default::default()
        };
        assert_eq!(query.scope_description(), "Path equals: /data/긴 파일 이름/trace.bin");
    }

    #[test]
    fn table_columns_keep_numeric_right_edges_for_different_value_lengths() {
        let ctx = egui::Context::default();
        let mut rows = Vec::new();
        for _ in 0..3 {
            rows.clear();
            let mut output = ctx.run_ui(Default::default(), |root| {
                egui::CentralPanel::default().show(root, |ui| {
                    for value in ["1", "123456789"] {
                        ui.horizontal(|ui| {
                            let number = io_table_cell(ui, 4, value, false);
                            let sector = io_table_cell(ui, 5, "8192", false);
                            rows.push((number.rect, sector.rect));
                        });
                    }
                });
            });
            output.textures_delta.clear();
        }
        assert_eq!(rows.len(), 2);
        assert!((rows[0].0.right() - rows[1].0.right()).abs() < 0.5);
        assert!((rows[0].1.right() - rows[1].1.right()).abs() < 0.5);
        assert!(rows.iter().all(|(number, sector)| number.right() < sector.left()));
    }
    #[test]
    fn request_table_keeps_headers_visible_after_vertical_scroll() {
        use android_ebpf_protocol::{BlockComplete, BlockIssue, StorageEvent};
        let mut app = StudioApp::default();
        for id in 1..=100_u64 {
            app.analyzer.ingest(StorageEvent::BlockIssue(BlockIssue {
                ts_ns: id * 1000, request_id: id, device_major: 8, device_minor: 0,
                sector: id * 8, sectors: 8, bytes: 4096, operation: IoOperation::Read,
                pid: 10, tid: 10, cpu: 0, comm: "reader".into(),
            }));
            app.analyzer.ingest(StorageEvent::BlockComplete(BlockComplete {
                cpu: None, ts_ns: id * 1000 + 100, request_id: id,
                device_major: 8, device_minor: 0, status: 0,
            }));
        }
        let ctx = egui::Context::default();
        let mut labels = Vec::new();
        fn collect(shape: &egui::Shape, labels: &mut Vec<(String, egui::Pos2)>) {
            match shape {
                egui::Shape::Text(text) => labels.push((text.galley.text().into(), text.pos)),
                egui::Shape::Vec(shapes) => for shape in shapes { collect(shape, labels); },
                _ => {}
            }
        }
        let mut header_y: Option<f32> = None;
        let mut first_times = Vec::new();
        for frame in 0..16 {
            let mut events = vec![egui::Event::PointerMoved(egui::pos2(250.0, 260.0))];
            if frame == 8 {
                events.push(egui::Event::MouseWheel {
                    unit: egui::MouseWheelUnit::Point, delta: egui::vec2(0.0, -220.0),
                    phase: egui::TouchPhase::Move,
                    modifiers: Default::default(),
                });
            }
            let mut output = ctx.run_ui(egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1000.0, 800.0))),
                time: Some(frame as f64 * 0.1), events, ..Default::default()
            }, |root| {
                egui::CentralPanel::default().show(root, |ui| app.table_ui(ui));
            });
            labels.clear();
            for shape in &output.shapes { collect(&shape.shape, &mut labels); }
            output.textures_delta.clear();
            if frame == 7 || frame == 15 {
                let header = labels.iter().find(|(text, _)| text == "Time ns")
                    .expect("Time column header must remain painted");
                if let Some(y) = header_y { assert!((header.1.y - y).abs() < 0.5); }
                header_y = Some(header.1.y);
                first_times.push(labels.iter().filter_map(|(text, _)| text.parse::<u64>().ok())
                    .filter(|value| *value > 1000 && *value % 1000 == 100).max());
            }
        }
        assert!(first_times.iter().all(Option::is_some));
        assert_ne!(first_times[0], first_times[1], "Body must actually scroll; unchanged header alone is insufficient");
    }

}
