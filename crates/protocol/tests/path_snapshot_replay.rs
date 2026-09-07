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

fn replay_changed(mut change: impl FnMut(&mut StorageEvent)) -> AnalysisEngine {
    let mut engine = AnalysisEngine::new();
    for line in include_str!("fixtures/pathless-tail.ndjson").lines() {
        let WireRecord::Event { mut event, .. } = serde_json::from_str(line).unwrap() else {
            continue;
        };
        change(&mut event);
        engine.ingest(event);
    }
    engine
}

fn read_origins(engine: &AnalysisEngine) -> Vec<FileOriginView> {
    let graph = engine.transaction_for(&engine.completed_ios()[0]);
    let request = graph
        .nodes
        .iter()
        .find(|node| node.kind == IoNodeKind::BlockRequest)
        .unwrap();
    graph.file_origins_for(request.node_id)
}

#[test]
fn later_renamed_path_does_not_replace_the_reading_syscall_path() {
    let mut seen = 0;
    let engine = replay_changed(|event| {
        if let StorageEvent::FileIo(file) = event {
            seen += 1;
            if seen == 2 {
                file.path = Some("/data/local/tmp/beta/renamed-A.bin".into());
                file.path_snapshot.as_mut().unwrap().path = file.path.clone();
            }
        }
    });
    let origins = read_origins(&engine);
    assert_eq!(
        origins[0].path.as_ref().unwrap().path.as_deref(),
        Some("/data/local/tmp/ebpf-acceptance-1788751800737/alpha/read-A.bin")
    );
}

#[test]
fn exact_inode_with_inferred_path_is_only_probable_filepath() {
    let engine = replay_changed(|event| {
        if let StorageEvent::RequestOrigin(origin) = event {
            origin.request_lifetime_confidence = EdgeConfidence::Exact;
        }
    });
    let origins = read_origins(&engine);
    assert_eq!(
        FilePathConfidence::from_origins(&origins),
        FilePathConfidence::Probable
    );
    let graph = engine.transaction_for(&engine.completed_ios()[0]);
    assert!(
        graph.edges.iter().any(|edge| edge
            .evidence
            .iter()
            .any(|e| e.match_type == "direct_bio_request")
            && edge.confidence == EdgeConfidence::Exact),
        "retain exact identity evidence separately"
    );
}

#[test]
fn conflicting_paths_without_a_contemporaneous_read_are_unresolved() {
    let mut seen = 0;
    let engine = replay_changed(|event| {
        if let StorageEvent::FileIo(file) = event {
            seen += 1;
            if seen == 1 {
                file.start_ts_ns += 10_000_000;
                file.end_ts_ns += 10_000_000;
            } else if seen == 2 {
                file.path = Some("/data/local/tmp/beta/other-link.bin".into());
                file.path_snapshot.as_mut().unwrap().path = file.path.clone();
            }
        }
    });
    let origins = read_origins(&engine);
    assert!(origins.iter().all(|origin| origin.path.is_none()));
    assert_eq!(
        FilePathConfidence::from_origins(&origins),
        FilePathConfidence::Unresolved
    );
}

#[test]
fn directly_recorded_exact_path_keeps_its_confidence() {
    let path = "/data/local/tmp/direct-origin.bin";
    let engine = replay_changed(|event| {
        if let StorageEvent::RequestOrigin(origin) = event {
            origin.request_lifetime_confidence = EdgeConfidence::Exact;
            origin.path = Some(PathSnapshot {
                path: Some(path.into()),
                source: PathSource::ProcFd,
                captured_ts_ns: origin.ts_ns,
                deleted: false,
            });
        }
    });
    let origins = read_origins(&engine);
    assert_eq!(
        origins[0].path.as_ref().unwrap().path.as_deref(),
        Some(path)
    );
    assert_eq!(
        FilePathConfidence::from_origins(&origins),
        FilePathConfidence::Exact
    );
}
