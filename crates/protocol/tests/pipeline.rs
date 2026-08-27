use android_ebpf_protocol::{
    AccessPattern, AnalysisEngine, BlockComplete, BlockInsert, BlockIssue, IoOperation,
    IoSizeClass, StorageEvent,
};

fn insert(id: u64, ts_ns: u64, sector: u64, bytes: u32) -> StorageEvent {
    StorageEvent::BlockInsert(BlockInsert {
        ts_ns,
        request_id: id,
        device_major: 259,
        device_minor: 0,
        sector,
        sectors: bytes / 512,
        bytes,
        operation: IoOperation::Read,
    })
}

fn issue(id: u64, ts_ns: u64, sector: u64, bytes: u32) -> StorageEvent {
    StorageEvent::BlockIssue(BlockIssue {
        ts_ns,
        request_id: id,
        device_major: 259,
        device_minor: 0,
        sector,
        sectors: bytes / 512,
        bytes,
        operation: IoOperation::Read,
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
fn pipeline_reports_queue_device_and_total_latency() {
    let mut engine = AnalysisEngine::new();
    engine.ingest(insert(1, 1_000_000, 100, 32 * 1024));
    engine.ingest(issue(1, 3_000_000, 100, 32 * 1024));
    let io = engine
        .ingest(complete(1, 8_000_000))
        .expect("request completes");

    assert_eq!(io.queue_latency_ns, Some(2_000_000));
    assert_eq!(io.device_latency_ns, 5_000_000);
    assert_eq!(io.total_latency_ns, 7_000_000);
    assert_eq!(io.size_class, IoSizeClass::Large);
    assert_eq!(io.access_pattern, AccessPattern::Unknown);
}

#[test]
fn utilization_is_union_of_overlapping_request_intervals() {
    let mut engine = AnalysisEngine::new();
    engine.ingest(issue(1, 1_000_000, 100, 4096));
    engine.ingest(issue(2, 3_000_000, 108, 4096));
    engine.ingest(complete(1, 5_000_000));
    engine.ingest(complete(2, 8_000_000));

    let summary = engine.summary();
    assert_eq!(summary.logging_ns, 7_000_000);
    assert_eq!(summary.busy_ns, 7_000_000);
    assert_eq!(summary.idle_ns, 0);
    assert_eq!(summary.category_summaries.len(), 2);
    assert_eq!(
        summary.category_summaries[1].access_pattern,
        AccessPattern::Sequential
    );
}

#[test]
fn slow_reason_bounds_large_cohort_work() {
    let mut engine = AnalysisEngine::new();
    let mut selected = None;
    for id in 1..=600 {
        let start = id * 1_000_000;
        engine.ingest(issue(id, start, id * 8, 4096));
        selected = engine.ingest(complete(id, start + id * 1_000));
    }

    let reason = engine
        .why_slow(selected.as_ref().expect("last request completes"))
        .expect("last request is slower than the cohort median");
    assert!(reason.cohort_samples <= 512);
}

#[test]
fn a_gap_between_requests_is_idle_time() {
    let mut engine = AnalysisEngine::new();
    engine.ingest(issue(1, 1_000_000, 100, 4096));
    engine.ingest(complete(1, 2_000_000));
    engine.ingest(issue(2, 5_000_000, 108, 4096));
    engine.ingest(complete(2, 8_000_000));

    let summary = engine.summary();
    assert_eq!(summary.logging_ns, 7_000_000);
    assert_eq!(summary.busy_ns, 4_000_000);
    assert_eq!(summary.idle_ns, 3_000_000);
}
