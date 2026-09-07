use android_ebpf_protocol::*;

fn replay(remove_paths: bool) -> AnalysisEngine {
    let mut engine = AnalysisEngine::new();
    for line in include_str!("fixtures/pathless-tail.ndjson").lines() {
        let WireRecord::Event { mut event, .. } = serde_json::from_str(line).unwrap() else {
            continue;
        };
        if remove_paths && let StorageEvent::FileIo(file) = &mut event {
            file.path = None;
            file.path_snapshot = None;
        }
        engine.ingest(event);
    }
    engine
}

#[test]
fn later_pathless_read_does_not_erase_recorded_path() {
    let engine = replay(false);
    assert_eq!(engine.completed_ios().len(), 1);
    let io = &engine.completed_ios()[0];
    assert_eq!(io.issue.operation, IoOperation::Read);
    let graph = engine.transaction_for(io);
    let request = graph
        .nodes
        .iter()
        .find(|node| node.kind == IoNodeKind::BlockRequest)
        .unwrap();
    let origins = graph.file_origins_for(request.node_id);
    assert_eq!(origins.len(), 1);
    assert_eq!(
        origins[0]
            .path
            .as_ref()
            .and_then(|snapshot| snapshot.path.as_deref()),
        Some("/data/local/tmp/ebpf-acceptance-1788751800737/alpha/read-A.bin")
    );
    assert_eq!(
        FilePathConfidence::from_origins(&origins),
        FilePathConfidence::Probable
    );
}

#[test]
fn identity_without_any_recorded_path_remains_unresolved() {
    let engine = replay(true);
    let graph = engine.transaction_for(&engine.completed_ios()[0]);
    let request = graph
        .nodes
        .iter()
        .find(|node| node.kind == IoNodeKind::BlockRequest)
        .unwrap();
    let origins = graph.file_origins_for(request.node_id);
    assert!(origins.iter().all(|origin| origin.path.is_none()));
    assert_eq!(
        FilePathConfidence::from_origins(&origins),
        FilePathConfidence::Unresolved
    );
}
