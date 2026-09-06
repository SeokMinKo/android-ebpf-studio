use android_ebpf_protocol::*;
use android_ebpf_studio::{perfetto::*, perfetto_projection::*, session};

fn event(id: u64, kind: BlockKind, timestamp_ns: u64, sector: u64) -> BlockEvent {
    BlockEvent {
        record_id: id,
        kind,
        timestamp_ns,
        cpu: Some(if kind == BlockKind::Issue { 2 } else { 7 }),
        tid: Some(if kind == BlockKind::Issue { 42 } else { 999 }),
        device_encoded: 2048,
        sector,
        sectors: 8,
        bytes: 4096,
        rwbs: "R".into(),
        comm: (kind == BlockKind::Issue).then(|| "worker".into()),
        error: None,
        clock: 0,
    }
}
fn fixture() -> DecodedTrace {
    DecodedTrace {
        events: vec![
            event(1, BlockKind::Issue, 100, 32),
            event(2, BlockKind::Complete, 200, 32),
            event(3, BlockKind::Complete, 300, 64),
        ],
        processes: vec![ProcessMetadata {
            snapshot_ns: Some(90),
            pid: 40,
            tid: Some(42),
            name: "app-candidate".into(),
            start_from_boot_ns: Some(10),
        }],
        quality: Default::default(),
    }
}

#[test]
fn whole_session_coverage_counts_perfetto_volume_without_joining_root_identifiers() {
    let trace = fixture();
    let projected = Projection::new(&trace).events(&analyze(&trace)).unwrap();
    let mut coverage = FilePathCoverageEngine::default();
    let mut expected = 0;
    for _ in 0..50_001 {
        for io in &projected {
            expected += 1;
            coverage.ingest(&StorageEvent::ObservedBlockCompletion(io.clone()));
        }
    }
    let result = coverage.finish();
    assert_eq!(result.completion_records(), expected);
    assert_eq!(result.unresolved.count, expected);
    assert_eq!(result.observation_without_file_identity, expected);
    assert_eq!(result.exact.count + result.probable.count, 0);
    assert_eq!(result.known_bytes(), expected * 4096);
}

#[test]
fn unsupported_clock_keeps_volume_without_a_session_origin_or_time_buckets() {
    let mut trace = fixture();
    for event in &mut trace.events {
        event.clock = 99;
    }
    let mut engine = AnalysisEngine::new();
    for io in Projection::new(&trace).events(&analyze(&trace)).unwrap() {
        engine.ingest(StorageEvent::ObservedBlockCompletion(io));
    }
    assert_eq!(engine.summary().completed_ios, 2);
    assert_eq!(engine.summary().read_bytes, 8192);
    assert_eq!(
        engine.session_start_ns(),
        None,
        "Unsupported clock must not establish the session's time origin"
    );
    assert!(
        engine.buckets().is_empty(),
        "Unsupported clock must not enter throughput/IOPS bins"
    );
    for summary in [
        engine.summary(),
        engine.live_summary(),
        engine.retained_summary(),
    ] {
        assert_eq!(summary.unplaced_time_ios, 2);
        assert_eq!(summary.logging_ns, None);
        assert_eq!(summary.busy_ns, None);
        assert_eq!(summary.idle_ns, None);
    }
    assert!(
        engine
            .completed_ios()
            .iter()
            .all(|io| io.completion_timestamp().is_none()
                && io.start_timestamp().is_none()
                && io.evidence.as_ref().unwrap().clock == 99)
    );
    for io in Projection::new(&fixture())
        .events(&analyze(&fixture()))
        .unwrap()
    {
        engine.ingest(StorageEvent::ObservedBlockCompletion(io));
    }
    for summary in [
        engine.summary(),
        engine.live_summary(),
        engine.retained_summary(),
    ] {
        assert_eq!(summary.completed_ios, 4);
        assert_eq!(summary.read_bytes, 16384);
        assert_eq!(summary.unplaced_time_ios, 2);
        assert_eq!(summary.logging_ns, None);
    }
    assert_eq!(engine.session_start_ns(), Some(100));
    assert_eq!(engine.known_time_span_ns(), Some(200));
    let known = engine.select_completed(|io| io.completion_timestamp().is_some());
    assert_eq!(known.summary().logging_ns, Some(200));
}

#[test]
fn unsupported_clock_replay_excludes_only_time_selection_and_csv_keeps_raw_evidence() {
    for mixed in [false, true] {
        let dir = std::env::temp_dir().join(format!("clock-scope-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("capture.ndjson");
        let mut trace = fixture();
        for e in &mut trace.events {
            if !mixed || e.record_id == 3 {
                e.clock = 99;
            }
        }
        let mut file = std::fs::File::create(&path).unwrap();
        for (i, io) in Projection::new(&trace)
            .events(&analyze(&trace))
            .unwrap()
            .into_iter()
            .enumerate()
        {
            write_record(
                &mut file,
                &WireRecord::Event {
                    schema_version: SCHEMA_VERSION,
                    sequence: i as u64,
                    event: StorageEvent::ObservedBlockCompletion(io),
                },
            )
            .unwrap();
        }
        drop(file);
        let original = std::fs::read(&path).unwrap();
        let full = session::load_analysis_window(&path, None, None).unwrap();
        assert_eq!(full.source_completed_ios, 2);
        assert_eq!(full.source_start_ns, mixed.then_some(100));
        assert_eq!(full.source_end_ns, mixed.then_some(200));
        assert_eq!(full.engine.summary().read_bytes, 8192);
        assert_eq!(full.engine.summary().logging_ns, None);
        let window = session::load_analysis_window(&path, Some((50, 350)), None).unwrap();
        assert_eq!(window.engine.summary().completed_ios, u64::from(mixed));
        assert_eq!(window.source_completed_ios, 2);
        let csv = dir.join("events.csv");
        let summary_path = session::export_csv(&path, &csv).unwrap();
        let mut reader = csv::Reader::from_path(csv).unwrap();
        let rows: Vec<_> = reader.records().map(Result::unwrap).collect();
        assert_eq!(rows.len(), 2);
        let row = rows.last().unwrap();
        assert_eq!(
            &row[1], "",
            "CSV normalized time must be missing, not raw or zero"
        );
        assert_eq!(&row[2], "");
        let raw: CompletedIo = serde_json::from_str(&row[17]).unwrap();
        assert_eq!(raw.completion.ts_ns, 300);
        assert_eq!(raw.evidence.unwrap().clock, 99);
        assert!(
            std::fs::read_to_string(summary_path)
                .unwrap()
                .contains("logging_ns,\n")
        );
        assert_eq!(
            session::load_analysis_window(&path, None, None)
                .unwrap()
                .engine
                .summary()
                .completed_ios,
            2
        );
        assert_eq!(std::fs::read(&path).unwrap(), original);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
#[test]
fn projected_completions_preserve_unknown_identity_timing_and_all_volume() {
    let trace = fixture();
    let projected = Projection::new(&trace).events(&analyze(&trace)).unwrap();
    assert_eq!(projected.len(), 2);
    let timed = &projected[0];
    let missing = &projected[1];
    assert_eq!((timed.issue.device_major, timed.issue.device_minor), (8, 0));
    assert_eq!(
        timed.issuer_cpu(),
        Some(2),
        "completion CPU must not become issue CPU"
    );
    assert_eq!(timed.issuer_tid(), Some(42));
    assert_eq!(timed.issuer_pid(), Some(40));
    assert_eq!(timed.total_latency_ns, Some(100));
    assert_eq!(timed.timing_confidence(), CorrelationConfidence::Probable);
    assert_eq!(
        timed.completion_status(),
        None,
        "absent status is not success"
    );
    assert_eq!(missing.issuer_pid(), None);
    assert_eq!(missing.issuer_tid(), None);
    assert_eq!(missing.issuer_cpu(), None);
    assert_eq!(missing.issue_timestamp(), None);
    assert_eq!(missing.total_latency_ns, None);
    let mut engine = AnalysisEngine::new();
    for io in projected {
        engine.ingest(StorageEvent::ObservedBlockCompletion(io));
    }
    let summary = engine.summary();
    assert_eq!(summary.completed_ios, 2);
    assert_eq!(summary.read_bytes, 8192);
    assert_eq!(summary.unmeasured_latency_ios, 1);
    assert_eq!(summary.p50_latency_ns, Some(100));
    assert_eq!(summary.max_queue_depth, None);
    assert_eq!(summary.busy_ns, None);
    assert_eq!(summary.idle_ns, None);
    for io in engine.completed_ios() {
        let graph = engine.transaction_for(io);
        assert!(
            graph
                .file_origins_for(block_request_node_id(io.issue.request_id))
                .is_empty()
        );
    }
    let missing = engine
        .select_completed(|io| io.total_latency_ns.is_none())
        .summary();
    assert_eq!(missing.read_bytes, 4096);
    assert_eq!(missing.p50_latency_ns, None);
}
#[test]
fn process_metadata_from_future_or_reused_tid_cannot_name_issuer() {
    for (snapshot, start) in [(101, 10), (90, 101)] {
        let mut trace = fixture();
        trace.processes[0].snapshot_ns = Some(snapshot);
        trace.processes[0].start_from_boot_ns = Some(start);
        let io = Projection::new(&trace)
            .events(&analyze(&trace))
            .unwrap()
            .remove(0);
        assert_eq!(io.issuer_pid(), None);
        assert_eq!(io.issuer_tid(), Some(42));
        assert_eq!(io.evidence.unwrap().process_name, None);
    }
}
#[test]
fn undated_or_contradictory_metadata_does_not_override_a_temporal_candidate() {
    let mut trace = fixture();
    let mut undated = trace.processes[0].clone();
    undated.snapshot_ns = None;
    undated.pid = 500;
    trace.processes.insert(0, undated);
    let io = Projection::new(&trace)
        .events(&analyze(&trace))
        .unwrap()
        .remove(0);
    assert_eq!(io.issuer_pid(), Some(40));
    let mut duplicate = trace.processes[1].clone();
    duplicate.pid = 501;
    trace.processes.push(duplicate);
    let io = Projection::new(&trace)
        .events(&analyze(&trace))
        .unwrap()
        .remove(0);
    assert_eq!(io.issuer_pid(), None);
}

#[test]
fn linux_userspace_device_encoding_round_trips_large_major_and_minor() {
    for (major, minor) in [(8u64, 0u64), (259, 1025), (0x12345678, 0x23456789)] {
        let encoded = (minor & 0xff)
            | ((major & 0xfff) << 8)
            | ((minor & !0xff) << 12)
            | ((major & !0xfff) << 32);
        assert_eq!(device_numbers(encoded), (major as u32, minor as u32));
    }
}
#[test]
fn session_window_and_csv_keep_unmeasured_completion_and_source_evidence() {
    let dir = std::env::temp_dir().join(format!("perfetto-projection-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("capture.ndjson");
    let trace = fixture();
    let ios = Projection::new(&trace).events(&analyze(&trace)).unwrap();
    let mut file = std::fs::File::create(&path).unwrap();
    write_record(&mut file,&WireRecord::SourceInfo{schema_version:SCHEMA_VERSION,source:"perfetto".into(),status:"Quality not fully measured".into(),metadata:serde_json::json!({"raw_trace":"perfetto/capture.pftrace","final_flush_outcome":0})}).unwrap();
    for (i, io) in ios.into_iter().enumerate() {
        write_record(
            &mut file,
            &WireRecord::Event {
                schema_version: SCHEMA_VERSION,
                sequence: i as u64 + 1,
                event: StorageEvent::ObservedBlockCompletion(io),
            },
        )
        .unwrap();
    }
    drop(file);
    let loaded = session::load_analysis_window(&path, Some((250, 350)), None).unwrap();
    assert_eq!(loaded.source_completed_ios, 2);
    assert_eq!(loaded.engine.summary().completed_ios, 1);
    assert_eq!(loaded.engine.summary().read_bytes, 4096);
    assert_eq!(loaded.engine.summary().p99_latency_ns, None);
    assert_eq!(loaded.engine.completed_ios()[0].issuer_tid(), None);
    assert_eq!(loaded.source_info.len(), 1);
    let csv = dir.join("events.csv");
    let summary = session::export_csv(&path, &csv).unwrap();
    let summary = std::fs::read_to_string(summary).unwrap();
    assert!(summary.contains("p50_latency_ns,100"));
    let raw = std::fs::read_to_string(&csv).unwrap();
    assert!(raw.contains("observed_block_completion"));
    // Every path is created exclusively by this test under its unique directory.
    std::fs::remove_dir_all(dir).unwrap();
}
