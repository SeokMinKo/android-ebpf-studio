use android_ebpf_protocol::{BlockComplete, BlockIssue, IoOperation, RequestCorrelator};

fn issue(ts_ns: u64) -> BlockIssue {
    BlockIssue {
        ts_ns,
        request_id: 0xabc,
        device_major: 8,
        device_minor: 0,
        sector: 128,
        sectors: 8,
        bytes: 4096,
        operation: IoOperation::Read,
        pid: 42,
        tid: 42,
        cpu: 3,
        comm: "fio".into(),
    }
}

#[test]
fn completion_computes_latency_and_removes_pending_request() {
    let mut correlator = RequestCorrelator::new(30_000_000_000);
    assert_eq!(correlator.on_issue(issue(1_000_000)), 1);

    let completed = correlator
        .on_complete(BlockComplete {
            ts_ns: 3_500_000,
            request_id: 0xabc,
            device_major: 8,
            device_minor: 0,
            status: 0,
        })
        .expect("issue must correlate");

    assert_eq!(completed.latency_ns, Some(2_500_000));
    assert_eq!(completed.issue.comm, "fio");
    assert_eq!(correlator.pending_len(), 0);
}

#[test]
fn mismatched_device_does_not_create_false_latency() {
    let mut correlator = RequestCorrelator::new(30_000_000_000);
    correlator.on_issue(issue(1_000));

    let result = correlator.on_complete(BlockComplete {
        ts_ns: 2_000,
        request_id: 0xabc,
        device_major: 8,
        device_minor: 1,
        status: 0,
    });

    assert!(result.is_none());
    assert_eq!(correlator.pending_len(), 1);
}

#[test]
fn duplicate_pending_key_is_rejected_instead_of_false_matched() {
    let mut correlator = RequestCorrelator::new(30_000_000_000);
    correlator.on_issue(issue(1_000));
    correlator.on_issue(issue(1_100));

    let result = correlator.on_complete(BlockComplete {
        ts_ns: 2_000,
        request_id: 0xabc,
        device_major: 8,
        device_minor: 0,
        status: 0,
    });

    assert!(result.is_none());
    assert_eq!(correlator.replaced_count(), 1);
}

#[test]
fn issue_depth_and_event_gaps_are_device_scoped_and_survive_filtering() {
    let mut engine = android_ebpf_protocol::AnalysisEngine::new();
    use android_ebpf_protocol::StorageEvent;
    for (id, device, ts) in [(1, 0, 10), (2, 0, 20), (3, 1, 25)] {
        let mut row = issue(ts);
        row.request_id = id;
        row.device_minor = device;
        row.pid = id as u32;
        engine.ingest(StorageEvent::BlockIssue(row));
    }
    for (id, device, ts) in [(2, 0, 30), (1, 0, 40), (3, 1, 50)] {
        engine.ingest(StorageEvent::BlockComplete(BlockComplete {
            request_id: id,
            device_major: 8,
            device_minor: device,
            ts_ns: ts,
            status: 0,
        }));
    }
    let rows = engine.completed_ios();
    assert_eq!(rows[0].detail_timing.issue_depth, Some(2));
    assert_eq!(rows[1].detail_timing.issue_depth, Some(1));
    assert_eq!(rows[2].detail_timing.issue_depth, Some(1));
    assert_eq!(rows[0].detail_timing.issue_gap_ns, Some(10));
    assert_eq!(rows[1].detail_timing.completion_gap_ns, Some(10));
    assert_eq!(rows[2].detail_timing.completion_gap_ns, None);
    let filtered = engine.select_completed(|io| io.issue.pid == 2);
    assert_eq!(
        filtered.completed_ios()[0].detail_timing.issue_depth,
        Some(2)
    );
    let mut legacy = serde_json::to_value(&rows[0]).unwrap();
    legacy.as_object_mut().unwrap().remove("detail_timing");
    let legacy: android_ebpf_protocol::CompletedIo = serde_json::from_value(legacy).unwrap();
    assert_eq!(
        legacy.detail_timing.issue_depth, None,
        "old sessions must not invent issue QD"
    );
}

#[test]
fn expired_and_duplicate_requests_do_not_leak_into_later_device_depth() {
    let mut c = RequestCorrelator::new(100);
    c.on_issue(issue(0));
    c.on_issue(issue(1)); // ambiguous ID removes its pending depth
    let mut next = issue(2);
    next.request_id = 2;
    c.on_issue(next);
    let io = c
        .on_complete(BlockComplete {
            ts_ns: 3,
            request_id: 2,
            device_major: 8,
            device_minor: 0,
            status: 0,
        })
        .unwrap();
    assert_eq!(io.detail_timing.issue_depth, Some(1));
    c.on_issue(issue(200));
    let mut next = issue(301);
    next.request_id = 3;
    c.on_issue(next); // TTL removes old pending
    let io = c
        .on_complete(BlockComplete {
            ts_ns: 302,
            request_id: 3,
            device_major: 8,
            device_minor: 0,
            status: 0,
        })
        .unwrap();
    assert_eq!(io.detail_timing.issue_depth, Some(1));
}
