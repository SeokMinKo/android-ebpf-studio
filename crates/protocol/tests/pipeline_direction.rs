use android_ebpf_protocol::*;

fn replay(overlap_write: bool) -> AnalysisEngine {
    let mut engine = AnalysisEngine::new();
    for line in include_str!("fixtures/read-log-write.ndjson").lines() {
        let WireRecord::Event { mut event, .. } = serde_json::from_str(line).unwrap() else {
            continue;
        };
        if overlap_write
            && let StorageEvent::FileIo(file) = &mut event
            && file.operation == IoOperation::Write
        {
            file.start_ts_ns = 54_695_478_800_000;
            file.end_ts_ns = 54_695_479_700_000;
        }
        engine.ingest(event);
    }
    engine
}

#[test]
fn adjacent_log_write_is_not_a_read_transaction_stage() {
    let engine = replay(false);
    let pipeline = engine.pipeline_for(&engine.completed_ios()[0]);
    let syscalls: Vec<_> = pipeline
        .spans
        .iter()
        .filter(|span| span.layer == PipelineLayer::Syscall)
        .collect();
    assert_eq!(
        syscalls.len(),
        1,
        "only the actual spanning Read syscall belongs to this Read"
    );
    assert_eq!(syscalls[0].name, "Read fd 3");
    assert_eq!(syscalls[0].duration_ns(), 808_229);
}

#[test]
fn overlapping_opposite_direction_syscall_is_not_a_read_stage() {
    let engine = replay(true);
    let graph = engine.transaction_for(&engine.completed_ios()[0]);
    assert!(
        !graph.nodes.iter().any(|node| node.name == "Write fd 1"),
        "known Write must not be relabeled as a Read syscall"
    );
}

#[test]
fn read_syscall_direction_size_and_task_are_preserved() {
    let engine = replay(false);
    let graph = engine.transaction_for(&engine.completed_ios()[0]);
    let syscall = graph
        .nodes
        .iter()
        .find(|node| node.kind == IoNodeKind::Syscall)
        .unwrap();
    assert_eq!(syscall.operation, Some(IoOperation::Read));
    assert_eq!(syscall.bytes, Some(262_144));
    assert_eq!((syscall.pid, syscall.tid), (6569, 6569));
}

#[test]
fn a_later_read_on_the_same_thread_is_not_a_stage_of_the_previous_request() {
    let mut engine = AnalysisEngine::new();
    for line in include_str!("fixtures/read-log-write.ndjson").lines() {
        let WireRecord::Event { mut event, .. } = serde_json::from_str(line).unwrap() else {
            continue;
        };
        if let StorageEvent::FileIo(file) = &mut event
            && file.operation == IoOperation::Write
        {
            file.operation = IoOperation::Read;
        }
        engine.ingest(event);
    }
    let pipeline = engine.pipeline_for(&engine.completed_ios()[0]);
    assert_eq!(
        pipeline
            .spans
            .iter()
            .filter(|span| span.layer == PipelineLayer::Syscall)
            .count(),
        1
    );
}
