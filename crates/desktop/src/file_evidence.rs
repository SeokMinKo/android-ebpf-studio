// Keep raw session evidence in the engine for attribution; expose only evidence
// related to the filtered block cohort in the file table and coverage counters.
fn coverage_percent(count: u64, total: u64) -> String {
    if total == 0 {
        return "N/A".into();
    }
    if count == 0 {
        return "0%".into();
    }
    if count == total {
        return "100%".into();
    }
    let value = ratio(count, total);
    if value < 0.1 {
        "<0.1%".into()
    } else if value > 99.9 {
        ">99.9%".into()
    } else {
        format!("{value:.1}%")
    }
}

#[test]
fn coverage_labels_do_not_round_missing_requests_into_perfect_resolution() {
    assert_eq!(coverage_percent(99_998, 100_001), ">99.9%");
    assert_eq!(coverage_percent(3, 100_001), "<0.1%");
    assert_eq!(coverage_percent(1, u64::MAX), "<0.1%");
    assert_eq!(coverage_percent(u64::MAX - 1, u64::MAX), ">99.9%");
    assert_eq!(coverage_percent(0, 184), "0%");
    assert_eq!(coverage_percent(184, 184), "100%");
    assert_eq!(coverage_percent(141, 184), "76.6%");
    assert_eq!(coverage_percent(0, 0), "N/A");
}

fn related_file_positions(engine: &AnalysisEngine) -> Vec<usize> {
    if engine.file_ios().is_empty() || engine.completed_ios().is_empty() {
        return Vec::new();
    }
    let mut direct = std::collections::HashSet::new();
    let mut identities = BTreeMap::<android_ebpf_protocol::FileIdentity, Vec<(u64, u64)>>::new();
    for io in engine.completed_ios() {
        let graph = engine.transaction_for(io);
        for node in &graph.nodes {
            if node.kind == IoNodeKind::FileOperation {
                direct.insert((node.start_ts_ns, node.end_or_start(), node.pid, node.tid));
            }
        }
        let low = io
            .insert
            .as_ref()
            .map_or(io.issue.ts_ns, |v| v.ts_ns)
            .saturating_sub(30_000_000_000);
        let high = io.completion.ts_ns.saturating_add(30_000_000_000);
        for origin in block_file_origins(&graph) {
            identities.entry(origin.file).or_default().push((low, high));
        }
    }
    let mut lookup = BTreeMap::<
        (u32, u32, u64),
        Vec<(android_ebpf_protocol::FileIdentity, Vec<(u64, u64)>)>,
    >::new();
    for (identity, mut intervals) in identities {
        intervals.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::new();
        for (start, end) in intervals {
            if let Some(last) = merged.last_mut()
                && start <= last.1
            {
                last.1 = last.1.max(end);
            } else {
                merged.push((start, end));
            }
        }
        lookup
            .entry((
                identity.fs_device_major,
                identity.fs_device_minor,
                identity.inode,
            ))
            .or_default()
            .push((identity, merged));
    }
    engine
        .file_ios()
        .iter()
        .enumerate()
        .filter_map(|(index, file)| {
            let linked = direct.contains(&(file.start_ts_ns, file.end_ts_ns, file.pid, file.tid))
                || file.file_identity.as_ref().is_some_and(|id| {
                    lookup
                        .get(&(id.fs_device_major, id.fs_device_minor, id.inode))
                        .is_some_and(|values| {
                            values.iter().any(|(candidate, intervals)| {
                                let compatible = !(id.inode_generation.is_some()
                                    && candidate.inode_generation.is_some()
                                    && id.inode_generation != candidate.inode_generation)
                                    && !(id.mount_id.is_some()
                                        && candidate.mount_id.is_some()
                                        && id.mount_id != candidate.mount_id);
                                let position =
                                    intervals.partition_point(|(_, end)| *end < file.start_ts_ns);
                                compatible
                                    && intervals
                                        .get(position)
                                        .is_some_and(|(start, _)| *start <= file.end_ts_ns)
                            })
                        })
                });
            linked.then_some(index)
        })
        .collect()
}

impl StudioApp {
    fn session_file_path_coverage_ui(&mut self, ui: &mut egui::Ui) {
        let Some(coverage) = &self.file_path_coverage else {
            ui.label("Whole-session FilePath coverage: available after session finalization or reopening saved data.");
            return;
        };
        let total = coverage.completion_records();
        if total == 0 {
            ui.label("Whole-session FilePath coverage: unavailable — no block completion records observed.");
            return;
        }
        let qa = self
            .render_qa
            .output
            .as_ref()
            .and_then(|_| std::env::var("ANDROID_EBPF_QA_GESTURE").ok());
        let qa_active = qa.as_ref().is_some_and(|g| g.starts_with("coverage-"));
        let start = ui.cursor().min;
        if qa_active && self.render_qa.frames >= 28 && self.render_qa.input_step == 0 {
            ui.scroll_to_rect(
                egui::Rect::from_min_size(start, egui::vec2(ui.available_width(), 300.0)),
                Some(egui::Align::Min),
            );
        }
        ui.label(
            egui::RichText::new(format!(
                "Whole session FilePath · {total} completion records · linked {}",
                coverage_percent(coverage.exact.count + coverage.probable.count, total)
            ))
            .strong(),
        );
        ui.horizontal_wrapped(|ui| {
            for (name, row) in [
                ("Exact", coverage.exact),
                ("Probable", coverage.probable),
                ("Unresolved", coverage.unresolved),
            ] {
                ui.label(format!(
                    "{name} {} ({})",
                    row.count,
                    coverage_percent(row.count, total)
                ));
            }
        });
        egui::CollapsingHeader::new("Coverage basis and unresolved reasons")
            .id_salt("whole-session-filepath-basis")
            .default_open(qa.as_deref() == Some("coverage-basis"))
            .show(ui, |ui| {
                ui.label("Percentages use observed block completion records, including unmatched completions. Whole-session results stay unchanged by detail filters and Compare selections. Pending issues, lost events and collector-suppressed I/O are outside this denominator; inspect capture diagnostics for those limits.");
                egui::Grid::new("whole-session-filepath-volume").striped(true).show(ui, |ui| {
                    ui.strong("FilePath"); ui.strong("Records"); ui.strong("Known request MiB"); ui.end_row();
                    for (name, row) in [("Exact", coverage.exact), ("Probable", coverage.probable), ("Unresolved", coverage.unresolved), ("Multiple origins (overlap)", coverage.multi_origin)] {
                        ui.label(name); ui.label(row.count.to_string()); ui.label(format!("{:.3}", row.known_bytes as f64 / 1_048_576.0)); ui.end_row();
                    }
                });
                ui.label(format!("Unresolved: no origin {} · identity without path {} · context-only {} · incomplete origin set {} · observations without joinable file identity {} · unmatched completions {}.", coverage.no_origin, coverage.missing_path, coverage.context_only, coverage.incomplete_origin_set, coverage.observation_without_file_identity, coverage.unmatched_completions));
                ui.label(format!("Unmatched completion bytes are unavailable ({} records). Issue events without a paired completion: {}. Multiple-origin records overlap confidence rows and are counted once in the denominator.", coverage.unmatched_completions, coverage.issue_events_without_completion));
            });
        if qa_active {
            let rect = egui::Rect::from_min_max(
                start,
                egui::pos2(ui.max_rect().right(), ui.cursor().top()),
            );
            self.render_qa
                .regions
                .insert("session-filepath-coverage".into(), (rect, ui.clip_rect()));
            if self.render_qa.latency_stable_rect == Some(rect) {
                self.render_qa.latency_stable_frames += 1;
            } else {
                self.render_qa.latency_stable_rect = Some(rect);
                self.render_qa.latency_stable_frames = 0;
            }
            if self.render_qa.frames >= 30
                && self.render_qa.latency_stable_frames >= 8
                && ui.clip_rect().contains(rect.center())
            {
                self.render_qa.input_step = 7;
            }
        }
        ui.add_space(8.0);
    }

    fn update_file_evidence_scope(&mut self) {
        self.file_evidence_positions = (self.query.active() || self.reanalysis.window.is_some())
            .then(|| related_file_positions(self.analysis()));
    }
}

#[cfg(test)]
mod file_scope_tests {
    use super::*;
    use android_ebpf_protocol::*;

    #[test]
    fn file_table_and_coverage_follow_filtered_request_cohort() {
        let mut app = StudioApp::default();
        for pid in [21u32, 22] {
            app.analyzer.ingest(StorageEvent::FileIo(FileIo {
                start_ts_ns: 90,
                end_ts_ns: 210,
                operation: IoOperation::Read,
                fd: 3,
                requested_bytes: 4096,
                completed_bytes: 4096,
                pid,
                tid: pid,
                comm: format!("p{pid}"),
                path: Some(format!("/data/p{pid}")),
                confidence: AttributionConfidence::Attributed,
                file_identity: Some(FileIdentity {
                    fs_device_major: 8,
                    fs_device_minor: 0,
                    inode: pid as u64,
                    inode_generation: None,
                    mount_id: None,
                }),
                path_snapshot: None,
                offset: Some(0),
                io_mode: FileIoMode::Direct,
                node_id: None,
            }));
            app.analyzer.ingest(StorageEvent::BlockIssue(BlockIssue {
                ts_ns: 100,
                request_id: pid as u64,
                device_major: 8,
                device_minor: 0,
                sector: pid as u64 * 8,
                sectors: 8,
                bytes: 4096,
                operation: IoOperation::Read,
                pid,
                tid: pid,
                cpu: 0,
                comm: format!("p{pid}"),
            }));
            app.analyzer
                .ingest(StorageEvent::BlockComplete(BlockComplete {
                    ts_ns: 200,
                    request_id: pid as u64,
                    device_major: 8,
                    device_minor: 0,
                    status: 0,
                }));
        }
        app.query.pid = 21;
        app.invalidate_query();
        app.rebuild_filtered();
        assert_eq!(app.analysis().completed_ios().len(), 1);
        assert_eq!(app.file_evidence_positions, Some(vec![0]));
        let summary = app.analysis_summary();
        assert_eq!((summary.file_ios, summary.attributed_file_ios), (1, 1));
        // Evidence retained internally cannot leak unrelated rows into the table.
        assert_eq!(app.analysis().file_ios().len(), 2);
        app.query.pid = 999;
        app.invalidate_query();
        app.rebuild_filtered();
        assert_eq!(app.file_evidence_positions, Some(vec![]));
        assert_eq!(app.analysis_summary().file_ios, 0);
        app.query = AnalysisFilter::default();
        app.invalidate_query();
        app.rebuild_filtered();
        assert_eq!(app.file_evidence_positions, None);
        assert_eq!(app.analysis_summary().file_ios, 2);
    }
}
