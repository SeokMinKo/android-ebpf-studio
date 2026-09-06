// Keep raw session evidence in the engine for attribution; expose only evidence
// related to the filtered block cohort in the file table and coverage counters.
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
                .ingest(StorageEvent::BlockComplete(BlockComplete {cpu:None,
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
