impl StudioApp {
    fn export_analysis_view(&mut self) {
        if self.is_running() {
            return;
        }
        let Some(path) = rfd::FileDialog::new()
            .set_file_name("storage-analysis-view.ndjson")
            .add_filter("Analysis view NDJSON", &["ndjson"])
            .save_file()
        else {
            return;
        };
        let engine = self.analysis().select_completed(|_| true);
        let mut summary = engine.summary();
        let evidence = related_file_positions(&engine);
        summary.file_ios = evidence.len() as u64;
        summary.attributed_file_ios = evidence
            .iter()
            .filter(|&&i| {
                matches!(
                    engine.file_ios()[i].confidence,
                    android_ebpf_protocol::AttributionConfidence::Attributed
                        | android_ebpf_protocol::AttributionConfidence::Exact
                )
            })
            .count() as u64;
        let metadata = serde_json::json!({"whole_session_file_path_coverage":self.file_path_coverage,"filepath_coverage_basis":"observed block completion records including unmatched; percentages by count; known bytes exclude unmatched; lost/pending/suppressed outside denominator","source_session":self.session_path,"source_completed_ios":self.reanalysis.source_count,"source_time_origin_ns":self.known_time_origin(),"completion_window_ns":self.reanalysis.window,"filters":self.query,"scope":"currently filtered completed block I/O and its file candidates; raw source is preserved separately","latency_definition":"total = insert (or issue when insert unavailable) to completion; queue = insert to issue when available; device = issue to completion","percentiles":"exact nearest-rank over loaded filtered completed requests","throughput_unit":"bytes / observation span; UI uses MiB/s","access_pattern":"original per-device and Read/Write block-sector adjacency; not recomputed after filtering"});
        let tx = self.tx.clone();
        self.status = "Exporting current analysis view in background…".into();
        std::thread::spawn(move || {
            let result = session::export_analysis_view(&path, &engine, &summary, metadata)
                .map(|_| path)
                .map_err(|e| e.to_string());
            let _ = tx.send(HostMessage::ViewExported(result));
        });
    }
}
