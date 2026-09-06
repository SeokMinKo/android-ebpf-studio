impl StudioApp {
    fn export_io_cohort_csv(&mut self,keys:Option<std::collections::HashSet<IoSelectionKey>>) {
        let Some(path)=rfd::FileDialog::new().set_file_name("storage-io-cohort.csv").add_filter("I/O CSV", &["csv"]).save_file() else {return;};
        if let Some(source)=&self.session_path && let Err(error)=session::ensure_distinct_export(source,&path) {self.status=error.to_string();return;}
        let engine=self.analysis().select_completed(|io|keys.as_ref().is_none_or(|k|k.contains(&selection_key(io))));
        let tx=self.tx.clone();self.status="Exporting full-resolution I/O cohort in background…".into();
        std::thread::spawn(move||{
            let result=session::export_completed_io_csv(&path,&engine).map(|_|path).map_err(|e|e.to_string());
            let _=tx.send(HostMessage::ViewExported(result));
        });
    }

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
        let metadata = serde_json::json!({"source_session":self.session_path,"source_completed_ios":self.reanalysis.source_count,"source_time_origin_ns":self.time_origin(),"completion_window_ns":self.reanalysis.window,"filters":self.query,"scope":"currently filtered completed block I/O and its file candidates; raw source is preserved separately","latency_definition":"total = insert (or issue when insert unavailable) to completion; queue = insert to issue when available; device = issue to completion","percentiles":"exact nearest-rank over loaded filtered completed requests","throughput_unit":"bytes / observation span; UI uses MiB/s","access_pattern":"original per-device and Read/Write block-sector adjacency; not recomputed after filtering"});
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
