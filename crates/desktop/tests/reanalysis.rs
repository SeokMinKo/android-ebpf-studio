use android_ebpf_protocol::*;
use android_ebpf_studio::session::{export_csv, load_analysis, load_analysis_window};
use std::{fs::File, io::BufWriter, path::PathBuf, sync::atomic::AtomicBool};

#[test]
fn reused_request_pointer_cannot_inherit_an_old_exact_file() {
    let mut engine = AnalysisEngine::new();
    let fixture = Fixture::new(2);
    let records = SessionReader::default()
        .read(std::io::BufReader::new(File::open(&fixture.0).unwrap()))
        .unwrap();
    // Two uses of pointer 1, then both delayed origin records.
    for ts in [1_000_000_000, 1_000_001_000] {
        engine.ingest(StorageEvent::BlockIssue(BlockIssue {
            ts_ns: ts,
            request_id: 1,
            device_major: 259,
            device_minor: 0,
            sector: 8,
            sectors: 8,
            bytes: 4096,
            operation: IoOperation::Read,
            pid: 21,
            tid: 22,
            cpu: 0,
            comm: "reuse".into(),
        }));
        engine.ingest(StorageEvent::BlockComplete(BlockComplete {
            ts_ns: ts + 100,
            request_id: 1,
            device_major: 259,
            device_minor: 0,
            status: 0,
        }));
    }
    let old = records
        .events
        .into_iter()
        .find_map(|e| {
            if let StorageEvent::RequestOrigin(v) = e {
                Some(v)
            } else {
                None
            }
        })
        .unwrap();
    for (ts, id, path) in [(1_000_000_000, 501, "/old"), (1_000_001_000, 502, "/new")] {
        let mut origin = old.clone();
        origin.ts_ns = ts;
        origin.origin_id = id;
        origin.file.inode = id;
        origin.path.as_mut().unwrap().path = Some(path.into());
        origin.path.as_mut().unwrap().captured_ts_ns = ts;
        engine.ingest(StorageEvent::RequestOrigin(origin));
    }
    for (position, path) in [(0, "/old"), (1, "/new")] {
        let projected = engine
            .select_completed(|io| io.issue.ts_ns == engine.completed_ios()[position].issue.ts_ns);
        let graph = projected.transaction_for(&projected.completed_ios()[0]);
        let block = graph
            .nodes
            .iter()
            .find(|n| n.kind == IoNodeKind::BlockRequest)
            .unwrap();
        let origins = graph.file_origins_for(block.node_id);
        assert_eq!(origins.len(), 1, "A reused pointer must not mix lifetimes");
        assert_eq!(
            origins[0].path.as_ref().unwrap().path.as_deref(),
            Some(path)
        );
    }
}

struct Fixture(PathBuf);
impl Fixture {
    fn new(count: u64) -> Self {
        let path =
            std::env::temp_dir().join(format!("studio-reanalysis-{}.ndjson", uuid::Uuid::new_v4()));
        let mut writer = BufWriter::new(File::create(&path).unwrap());
        let mut sequence = 0;
        let mut emit = |event| {
            sequence += 1;
            write_record(
                &mut writer,
                &WireRecord::Event {
                    schema_version: SCHEMA_VERSION,
                    sequence,
                    event,
                },
            )
            .unwrap();
        };
        for i in 0..count {
            let ts = 1_000_000_000 + i * 10_000_000;
            emit(StorageEvent::BlockIssue(BlockIssue {
                ts_ns: ts,
                request_id: i,
                device_major: 259,
                device_minor: 0,
                sector: i * 8,
                sectors: 8,
                bytes: 4096,
                operation: IoOperation::Read,
                pid: 21,
                tid: 22,
                cpu: 0,
                comm: "known-reader".into(),
            }));
            emit(StorageEvent::BlockComplete(BlockComplete {
                ts_ns: ts + 100,
                request_id: i,
                device_major: 259,
                device_minor: 0,
                status: 0,
            }));
        }
        // Delayed delivery after all block events must still reconstruct the old file.
        emit(StorageEvent::RequestOrigin(RequestOrigin {
            ts_ns: 1_010_000_000,
            request_id: 1,
            origin_id: 500,
            file: FileIdentity {
                fs_device_major: 259,
                fs_device_minor: 0,
                inode: 123,
                inode_generation: None,
                mount_id: None,
            },
            path: Some(PathSnapshot {
                path: Some("/data/old-window.bin".into()),
                source: PathSource::ProcFd,
                captured_ts_ns: 1_010_000_000,
                deleted: false,
            }),
            origin: IoOrigin::File,
            operation: IoOperation::Read,
            bytes: Some(4096),
            pid: 21,
            tid: 22,
            file_origin_confidence: EdgeConfidence::Exact,
            request_lifetime_confidence: EdgeConfidence::Exact,
            incomplete: false,
        }));
        write_record(
            &mut writer,
            &WireRecord::Footer {
                schema_version: SCHEMA_VERSION,
                events_seen: sequence,
                events_persisted: sequence,
                events_dropped: 0,
                events_rejected: 0,
                graceful: Some(true),
            },
        )
        .unwrap();
        drop(writer);
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn old_window_recovers_evicted_io_and_delayed_exact_file_without_reclassifying() {
    let fixture = Fixture::new(100_020);
    let full = load_analysis(&fixture.0).unwrap();
    assert_eq!(full.source_completed_ios, 100_020);
    assert!(
        !full
            .engine
            .completed_ios()
            .iter()
            .any(|io| io.issue.request_id == 1)
    );
    drop(full);
    let view =
        load_analysis_window(&fixture.0, Some((1_010_000_100, 1_020_000_100)), None).unwrap();
    assert_eq!(view.source_start_ns, 1_000_000_000);
    assert_eq!(view.engine.completed_ios().len(), 2);
    let io = &view.engine.completed_ios()[0];
    assert_eq!(io.issue.request_id, 1);
    assert_eq!(io.access_pattern, AccessPattern::Sequential);
    assert_eq!(io.total_latency_ns, Some(100));
    assert_eq!(io.queue_depth_after, Some(0));
    let graph = view.engine.transaction_for(io);
    let origins = graph.file_origins_for(block_request_node_id(1));
    assert_eq!(origins.len(), 1);
    assert_eq!(origins[0].confidence, EdgeConfidence::Exact);
    assert_eq!(
        origins[0].path.as_ref().unwrap().path.as_deref(),
        Some("/data/old-window.bin")
    );
    assert_eq!(view.integrity_ok, Some(true));
    assert!(
        load_analysis_window(&fixture.0, Some((1_000_000_000, u64::MAX)), None)
            .unwrap_err()
            .to_string()
            .contains("100,000")
    );
}

#[test]
fn cancellation_empty_window_and_invalid_window_are_explicit() {
    let fixture = Fixture::new(3);
    assert!(load_analysis_window(&fixture.0, Some((3, 2)), None).is_err());
    assert!(
        load_analysis_window(&fixture.0, None, Some(&AtomicBool::new(true)))
            .unwrap_err()
            .to_string()
            .contains("cancelled")
    );
    let empty = load_analysis_window(&fixture.0, Some((1, 2)), None).unwrap();
    assert!(empty.engine.completed_ios().is_empty());
    assert_eq!(empty.source_completed_ios, 3);
}

#[test]
fn streamed_export_keeps_all_raw_events_including_old_file_evidence() {
    let fixture = Fixture::new(20);
    let csv = fixture.0.with_extension("csv");
    let summary = export_csv(&fixture.0, &csv).unwrap();
    let rows: Vec<_> = csv::Reader::from_path(&csv)
        .unwrap()
        .records()
        .map(Result::unwrap)
        .collect();
    assert_eq!(rows.len(), 41);
    assert!(
        rows.iter()
            .any(|r| r.get(12) == Some("/data/old-window.bin"))
    );
    std::fs::remove_file(csv).unwrap();
    std::fs::remove_file(summary).unwrap();
}

#[test]
fn view_export_contains_only_selected_io_and_preserves_path_provenance() {
    let fixture = Fixture::new(20);
    let loaded =
        load_analysis_window(&fixture.0, Some((1_010_000_100, 1_020_000_100)), None).unwrap();
    let summary = loaded.engine.summary();
    assert_eq!(summary.logging_ns, 10_000_100);
    let output = fixture.0.with_extension("view.ndjson");
    android_ebpf_studio::session::export_analysis_view(
        &output,
        &loaded.engine,
        &summary,
        serde_json::json!({"source_session":fixture.0,"completion_window_ns":loaded.window_ns}),
    )
    .unwrap();
    let text = std::fs::read_to_string(&output).unwrap();
    let rows: Vec<serde_json::Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0]["request_count"], 2);
    assert_eq!(rows[0]["summary"]["completed_ios"], 2);
    assert_eq!(
        rows[1]["file_candidates"][0]["path"]["path"],
        "/data/old-window.bin"
    );
    assert_eq!(rows[1]["file_candidates"][0]["edge_confidence"], "exact");
    std::fs::remove_file(output).unwrap();
}

#[test]
fn export_cannot_overwrite_the_original_session() {
    let fixture = Fixture::new(3);
    let before = std::fs::read(&fixture.0).unwrap();
    assert!(export_csv(&fixture.0, &fixture.0).is_err());
    let loaded = load_analysis(&fixture.0).unwrap();
    assert!(
        android_ebpf_studio::session::export_analysis_view(
            &fixture.0,
            &loaded.engine,
            &loaded.engine.summary(),
            serde_json::json!({"source_session":fixture.0})
        )
        .is_err()
    );
    assert_eq!(std::fs::read(&fixture.0).unwrap(), before);
}
