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

    assert_eq!(completed.latency_ns, 2_500_000);
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
