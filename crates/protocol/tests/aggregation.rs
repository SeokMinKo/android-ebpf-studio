use android_ebpf_protocol::{AnalysisEngine, BlockComplete, BlockIssue, IoOperation, StorageEvent};

fn issue(id: u64, ts_ns: u64, bytes: u32, operation: IoOperation) -> StorageEvent {
    StorageEvent::BlockIssue(BlockIssue {
        ts_ns,
        request_id: id,
        device_major: 259,
        device_minor: 0,
        sector: id * 8,
        sectors: bytes / 512,
        bytes,
        operation,
        pid: 99,
        tid: 99,
        cpu: 1,
        comm: "fio".into(),
    })
}

fn complete(id: u64, ts_ns: u64) -> StorageEvent {
    StorageEvent::BlockComplete(BlockComplete {
        ts_ns,
        request_id: id,
        device_major: 259,
        device_minor: 0,
        status: 0,
    })
}

#[test]
fn aggregate_reports_bytes_iops_queue_depth_and_percentiles() {
    let mut engine = AnalysisEngine::new();
    for event in [
        issue(1, 1_000_000, 4_096, IoOperation::Read),
        issue(2, 2_000_000, 8_192, IoOperation::Write),
        complete(1, 2_000_000),
        complete(2, 5_000_000),
    ] {
        engine.ingest(event);
    }

    let summary = engine.summary();
    assert_eq!(summary.completed_ios, 2);
    assert_eq!(summary.read_bytes, 4_096);
    assert_eq!(summary.write_bytes, 8_192);
    assert_eq!(summary.max_queue_depth, 2);
    assert_eq!(summary.p50_latency_ns, Some(1_000_000));
    assert_eq!(summary.p95_latency_ns, Some(3_000_000));
    assert_eq!(summary.p99_latency_ns, Some(3_000_000));
}
