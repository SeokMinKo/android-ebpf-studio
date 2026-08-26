use android_ebpf_protocol::{
    AccessPattern, BlockIssue, IoOperation, IoSizeClass, SequentialClassifier,
};

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
fn adjacent_requests_are_sequential_even_after_a_long_gap() {
    let mut classifier = SequentialClassifier::new();

    assert_eq!(
        classifier.classify(&issue(1_000, 100)),
        AccessPattern::Unknown
    );
    assert_eq!(
        classifier.classify(&issue(60_000_000_000, 108)),
        AccessPattern::Sequential
    );
}

#[test]
fn sector_jump_is_random() {
    let mut classifier = SequentialClassifier::new();

    classifier.classify(&issue(1_000, 100));
    assert_eq!(
        classifier.classify(&issue(2_000, 4_096)),
        AccessPattern::Random
    );
}

#[test]
fn read_and_write_keep_independent_continuity() {
    let mut classifier = SequentialClassifier::new();
    classifier.classify(&issue(1_000, 100));
    let mut write = issue(2_000, 108);
    write.operation = IoOperation::Write;
    assert_eq!(classifier.classify(&write), AccessPattern::Unknown);
    assert_eq!(
        classifier.classify(&issue(3_000, 108)),
        AccessPattern::Sequential
    );
}

#[test]
fn thirty_two_kib_is_large_and_the_byte_below_is_small() {
    assert_eq!(IoSizeClass::classify(32 * 1024 - 1), IoSizeClass::Small);
    assert_eq!(IoSizeClass::classify(32 * 1024), IoSizeClass::Large);
}
