use android_ebpf_protocol::{AnalysisEngine, BlockComplete, BlockIssue, IoOperation, StorageEvent};

fn issue(id: u64, ts_ns: u64) -> StorageEvent {
    StorageEvent::BlockIssue(BlockIssue {
        ts_ns,
        request_id: id,
        device_major: 8,
        device_minor: 0,
        sector: id * 8,
        sectors: 8,
        bytes: 4096,
        operation: IoOperation::Read,
        pid: id as u32,
        tid: id as u32,
        cpu: 0,
        comm: "queue-fixture".into(),
    })
}
fn complete(id: u64, ts_ns: u64) -> StorageEvent {
    StorageEvent::BlockComplete(BlockComplete {
        ts_ns,
        request_id: id,
        device_major: 8,
        device_minor: 0,
        status: 0,
    })
}

#[test]
fn retained_serial_request_keeps_the_observed_issue_peak() {
    let mut engine = AnalysisEngine::new();
    engine.ingest(issue(1, 10));
    engine.ingest(complete(1, 20));
    assert_eq!(engine.summary().max_queue_depth, Some(1));
    assert_eq!(
        engine.retained_summary().max_queue_depth,
        Some(1),
        "a completed serial request was observed in flight at issue"
    );
    assert_eq!(
        engine.select_completed(|_| true).summary().max_queue_depth,
        Some(1)
    );
}

#[test]
fn later_low_depth_issue_does_not_erase_the_peak_in_its_time_bucket() {
    let mut engine = AnalysisEngine::new();
    for e in [
        issue(1, 10),
        issue(2, 20),
        complete(1, 30),
        complete(2, 40),
        issue(3, 50),
    ] {
        engine.ingest(e);
    }
    assert_eq!(engine.summary().max_queue_depth, Some(2));
    assert_eq!(engine.buckets()[0].max_queue_depth, Some(2));
}

#[test]
fn filtering_and_window_replay_keep_original_depth_and_issue_time_bucket() {
    let events = [
        issue(1, 10),
        issue(2, 20),
        complete(1, 1_000_000_010),
        complete(2, 1_000_000_020),
    ];
    let mut engine = AnalysisEngine::new();
    for e in events.clone() {
        engine.ingest(e);
    }
    let selected = engine.select_completed(|io| io.issue.request_id == 2);
    let io = &selected.completed_ios()[0];
    assert_eq!(io.queue_depth_at_issue, Some(2));
    assert_eq!(io.queue_depth_after, Some(0));
    assert_eq!(selected.summary().max_queue_depth, Some(2));
    assert_eq!(selected.summary().measured_queue_depth_ios, 1);
    assert_eq!(selected.buckets()[0].max_queue_depth, Some(2));
    assert_eq!(
        selected.buckets()[1].max_queue_depth,
        None,
        "completion bins must not substitute post-completion depth"
    );
    let mut replay = AnalysisEngine::new();
    replay.set_completion_window(1_000_000_020, 1_000_000_020);
    for e in events {
        replay.ingest(e);
    }
    assert_eq!(replay.completed_ios(), selected.completed_ios());
    assert_eq!(replay.retained_summary().max_queue_depth, Some(2));
}

#[test]
fn old_projected_completions_and_mixed_sources_do_not_invent_issue_depth() {
    let mut engine = AnalysisEngine::new();
    engine.ingest(issue(1, 10));
    let io = engine.ingest(complete(1, 20)).unwrap();
    let mut legacy = serde_json::to_value(&io).unwrap();
    legacy
        .as_object_mut()
        .unwrap()
        .remove("queue_depth_at_issue");
    let mut old: android_ebpf_protocol::CompletedIo = serde_json::from_value(legacy).unwrap();
    assert_eq!(old.queue_depth_at_issue, None);
    assert_eq!(old.queue_depth_after, Some(0));
    old.issue.request_id = 2;
    old.completion.request_id = 2;
    old.queue_depth_after = Some(99);
    let mut projected = AnalysisEngine::new();
    projected.ingest(StorageEvent::ObservedBlockCompletion(old));
    assert_eq!(projected.retained_summary().max_queue_depth, None);
    assert_eq!(projected.summary().measured_queue_depth_ios, 0);
    projected.ingest(StorageEvent::ObservedBlockCompletion(io));
    assert_eq!(projected.summary().max_queue_depth, Some(1));
    assert_eq!(projected.summary().measured_queue_depth_ios, 1);
    assert_eq!(projected.summary().completed_ios, 2);
    assert_eq!(projected.retained_summary().max_queue_depth, Some(1));
}

#[test]
fn depth_context_includes_other_devices_and_survives_detail_eviction() {
    let mut engine = AnalysisEngine::new();
    engine.ingest(issue(1, 10));
    let StorageEvent::BlockIssue(mut other) = issue(2, 20) else {
        unreachable!()
    };
    other.device_minor = 1;
    engine.ingest(StorageEvent::BlockIssue(other));
    let StorageEvent::BlockComplete(mut done) = complete(2, 30) else {
        unreachable!()
    };
    done.device_minor = 1;
    let io = engine.ingest(StorageEvent::BlockComplete(done)).unwrap();
    assert_eq!(io.queue_depth_at_issue, Some(2));
    assert_eq!(io.queue_depth_after, Some(1));
    let selected = engine.select_completed(|io| io.issue.device_minor == 1);
    assert_eq!(selected.retained_summary().max_queue_depth, Some(2));
    let mut large = AnalysisEngine::new();
    for id in 0..100_001 {
        let mut sample = io.clone();
        sample.issue.request_id = id;
        sample.completion.request_id = id;
        sample.queue_depth_at_issue = Some(if id < 10_000 { 9 } else { 2 });
        large.ingest(StorageEvent::ObservedBlockCompletion(sample));
    }
    assert_eq!(large.summary().max_queue_depth, Some(9));
    assert_eq!(large.retained_summary().max_queue_depth, Some(2));
    assert_eq!(large.retained_summary().measured_queue_depth_ios, 90_001);
}
