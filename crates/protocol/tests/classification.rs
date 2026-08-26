use android_ebpf_protocol::{AccessPattern, BlockIssue, IoOperation, SequentialClassifier};

fn issue(ts_ns: u64, sector: u64) -> BlockIssue {
    BlockIssue {
        ts_ns,
        request_id: sector,
        device_major: 259,
        device_minor: 0,
        sector,
        sectors: 8,
        bytes: 4096,
        operation: IoOperation::Read,
        pid: 7,
        tid: 7,
        cpu: 0,
        comm: "reader".into(),
    }
}

#[test]
fn adjacent_requests_within_window_are_sequential() {
    let mut classifier = SequentialClassifier::new(10_000_000);

    assert_eq!(
        classifier.classify(&issue(1_000, 100)),
        AccessPattern::Unknown
    );
    assert_eq!(
        classifier.classify(&issue(2_000, 108)),
        AccessPattern::Sequential
    );
}

#[test]
fn sector_jump_or_expired_window_is_random() {
    let mut classifier = SequentialClassifier::new(10_000);

    classifier.classify(&issue(1_000, 100));
    assert_eq!(
        classifier.classify(&issue(2_000, 4_096)),
        AccessPattern::Random
    );
    assert_eq!(
        classifier.classify(&issue(50_000, 4_104)),
        AccessPattern::Random
    );
}
