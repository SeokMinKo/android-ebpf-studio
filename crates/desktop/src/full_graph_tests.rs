#[cfg(test)]
mod full_graph_tests {
    use super::*;
    use android_ebpf_protocol::{BlockComplete, BlockIssue, StorageEvent};
    #[test]
    fn unknown_clock_stays_unplaced_in_every_time_preset_and_csv() {
        let mut native = AnalysisEngine::new();
        native.ingest(StorageEvent::BlockIssue(BlockIssue {
            ts_ns: 1,
            request_id: 1,
            device_major: 8,
            device_minor: 0,
            sector: 1,
            sectors: 8,
            bytes: 4096,
            operation: IoOperation::Read,
            pid: 1,
            tid: 1,
            cpu: 0,
            comm: "missing".into(),
        }));
        let mut io = native
            .ingest(StorageEvent::BlockComplete(BlockComplete {
                cpu: None,
                ts_ns: 10,
                request_id: 1,
                device_major: 8,
                device_minor: 0,
                status: 0,
            }))
            .unwrap();
        io.total_latency_ns = None;
        io.device_latency_ns = None;
        io.evidence = Some(Box::new(android_ebpf_protocol::CompletionEvidence {
            source: "fixture".into(),
            record_id: 1,
            issue_record_candidates: vec![],
            issue_timestamp_ns: None,
            issuer_pid: None,
            issuer_tid: None,
            issuer_cpu: None,
            completion_status: None,
            process_name: None,
            timing_confidence: android_ebpf_protocol::CorrelationConfidence::ContextOnly,
            reason: "unknown clock".into(),
            clock: 99,
        }));
        let mut engine = AnalysisEngine::new();
        engine.ingest(StorageEvent::ObservedBlockCompletion(io));
        for preset in ExplorerPreset::ALL {
            let (x, y, _) = preset.query().unwrap_or((
                AxisMetric::TimeMs,
                AxisMetric::ChunkKiB,
                GroupBy::Direction,
            ));
            if y == AxisMetric::SchedulerIoWait {
                continue;
            }
            let bw = BandwidthContext {
                activity: Arc::default(),
                range: (0, 100),
                devices: vec![(8, 0)],
            };
            let s = compute_graph_selection(
                &engine,
                SelectionRequest::Rectangle {
                    min: [f64::NEG_INFINITY; 2],
                    max: [f64::INFINITY; 2],
                },
                x,
                y,
                0,
                bw,
                1000,
            );
            assert!(
                s.keys.is_empty(),
                "{preset:?} must not place an unsupported clock"
            );
        }
        let s = compute_selection(
            &engine,
            SelectionRequest::Rectangle {
                min: [f64::NEG_INFINITY; 2],
                max: [f64::INFINITY; 2],
            },
            AxisMetric::Category(CategoryAxis::Command),
            AxisMetric::ChunkKiB,
            0,
        );
        assert_eq!(s.keys.len(), 1);
        assert_eq!(s.read.bytes, 4096);
        assert_eq!(s.unplaced_time_count, 1);
        let path =
            std::env::temp_dir().join(format!("unknown-clock-export-{}.csv", uuid::Uuid::new_v4()));
        session::export_completed_io_csv(&path, &engine).unwrap();
        let rows = csv::Reader::from_path(&path)
            .unwrap()
            .records()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(&rows[0][3], "");
        assert!(rows[0][20].contains("99"));
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn every_explore_graph_handles_empty_single_mixed_and_large_filtered_cohorts() {
        let mut checks = 0;
        for count in [0usize, 1, 9, 10_005] {
            let mut engine = AnalysisEngine::new();
            let mut activity = crate::host_bw::ActivityTimeline::default();
            for id in 1..=count as u64 {
                let op = match id % 3 {
                    0 => IoOperation::Discard,
                    1 => IoOperation::Read,
                    _ => IoOperation::Write,
                };
                engine.ingest(StorageEvent::BlockIssue(BlockIssue {
                    ts_ns: id * 2_000_000,
                    request_id: id,
                    device_major: 8,
                    device_minor: 0,
                    sector: id * 16,
                    sectors: 8,
                    bytes: 4096,
                    operation: op,
                    pid: 1,
                    tid: 1,
                    cpu: 0,
                    comm: "fixture".into(),
                }));
                if let Some(io) = engine.ingest(StorageEvent::BlockComplete(BlockComplete {
                    cpu: Some(1),
                    ts_ns: id * 2_000_000 + 1_000_000,
                    request_id: id,
                    device_major: 8,
                    device_minor: 0,
                    status: 0,
                })) {
                    activity.observe(&io);
                }
            }
            activity.verified_complete = true;
            for operation in [None, Some(IoOperation::Read), Some(IoOperation::Write)] {
                let filtered = engine
                    .select_completed(|io| operation.is_none_or(|op| io.issue.operation == op));
                let n = filtered.completed_ios().len();
                for preset in ExplorerPreset::ALL {
                    let (x, y, _) = preset.query().unwrap_or((
                        AxisMetric::TimeMs,
                        AxisMetric::ChunkKiB,
                        GroupBy::Direction,
                    ));
                    if y == AxisMetric::SchedulerIoWait {
                        continue;
                    } // Independent scheduler population has its own fixture/matrix.
                    let bw = BandwidthContext {
                        activity: Arc::new(activity.clone()),
                        range: (0, (count as u64 + 1) * 2_000_000),
                        devices: vec![(8, 0)],
                    };
                    let s = compute_graph_selection(
                        &filtered,
                        SelectionRequest::Rectangle {
                            min: [f64::NEG_INFINITY; 2],
                            max: [f64::INFINITY; 2],
                        },
                        x,
                        y,
                        0,
                        bw,
                        1000,
                    );
                    assert!(s.keys.len() <= n, "{count} {preset:?}");
                    assert_eq!(
                        s.metric
                            .total
                            .histogram(16)
                            .iter()
                            .map(|b| b.count)
                            .sum::<usize>(),
                        s.metric.total.values.len()
                    );
                    if matches!(
                        y,
                        AxisMetric::ChunkKiB
                            | AxisMetric::Sector
                            | AxisMetric::TotalLatencyMs
                            | AxisMetric::IssueQueueDepth
                            | AxisMetric::IssueCpu
                            | AxisMetric::Timeline(_)
                    ) {
                        assert_eq!(s.keys.len(), n, "{count} {operation:?} {preset:?}");
                    }
                    if y == AxisMetric::ChunkKiB && n > 0 {
                        assert_eq!(s.metric.total.percentile(50), Some(4.));
                    }
                    if y == AxisMetric::TotalLatencyMs && n > 0 {
                        assert_eq!(s.metric.total.percentile(95), Some(1.));
                    }
                    if y == AxisMetric::IssueQueueDepth && n > 0 {
                        assert_eq!(s.metric.total.percentile(100), Some(1.));
                    }
                    for (dimension, rows) in &s.categories {
                        if !dimension.contains("membership") {
                            assert_eq!(
                                rows.values().map(|v| v.0).sum::<u64>() as usize,
                                s.keys.len(),
                                "{dimension}"
                            );
                        }
                    }
                    if let Some(bw) = s.host_bw {
                        assert_eq!(bw.busy_ns, Some(count as u64 * 1_000_000));
                        assert_eq!(bw.idle_ns, Some((count as u64 + 2) * 1_000_000));
                    }
                    checks += 1;
                }
            }
        }
        assert_eq!(checks, 336);
    }
}
