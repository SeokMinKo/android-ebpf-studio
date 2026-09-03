use android_ebpf_protocol::{
    AnalysisEngine, BlockComplete, BlockIssue, EdgeConfidence, FileIdentity, FileIo, FileIoMode,
    IoEdge, IoNode, IoNodeKind, IoOperation, IoOrigin, IoRelation, IoTransactionGraph,
    PathSnapshot, PathSource, RequestOrigin, StorageEvent,
};

fn node(id: u64, kind: IoNodeKind, start: u64, end: u64) -> IoNode {
    let is_file_operation = kind == IoNodeKind::FileOperation;
    IoNode {
        node_id: id,
        transaction_id: Some(77),
        kind,
        start_ts_ns: start,
        end_ts_ns: Some(end),
        origin: IoOrigin::File,
        file: is_file_operation.then(|| FileIdentity {
            fs_device_major: 259,
            fs_device_minor: 7,
            inode: 100 + id,
            inode_generation: None,
            mount_id: Some(42),
        }),
        path: is_file_operation.then(|| PathSnapshot {
            path: Some(format!("/data/file-{id}.bin")),
            source: PathSource::ProcFd,
            captured_ts_ns: start,
            deleted: false,
        }),
        operation: Some(IoOperation::Read),
        bytes: Some(4096),
        pid: 10,
        tid: 11,
        name: format!("node-{id}"),
    }
}

#[test]
fn graph_keeps_multiple_file_origins_for_one_request() {
    let mut graph = IoTransactionGraph::new(77);
    graph
        .add_node(node(1, IoNodeKind::FileOperation, 100, 200))
        .unwrap();
    graph
        .add_node(node(2, IoNodeKind::FileOperation, 110, 210))
        .unwrap();
    graph
        .add_node(node(3, IoNodeKind::BlockRequest, 220, 500))
        .unwrap();
    for edge_id in 10..=11 {
        graph
            .add_edge(IoEdge {
                edge_id,
                transaction_id: Some(77),
                from_node_id: edge_id - 9,
                to_node_id: 3,
                relation: IoRelation::MergedInto,
                confidence: EdgeConfidence::Exact,
                evidence: Vec::new(),
            })
            .unwrap();
    }

    let origins = graph.file_origins_for(3);
    assert_eq!(origins.len(), 2);
    assert_ne!(origins[0].file, origins[1].file);
}

#[test]
fn graph_rejects_cycles_and_computes_non_overlapping_time() {
    let mut graph = IoTransactionGraph::new(88);
    graph.add_node(node(1, IoNodeKind::Vfs, 0, 100)).unwrap();
    graph
        .add_node(node(2, IoNodeKind::Filesystem, 20, 80))
        .unwrap();
    graph
        .add_node(node(3, IoNodeKind::BlockRequest, 110, 200))
        .unwrap();
    graph
        .add_edge(IoEdge::exact(1, 1, 2, IoRelation::Calls))
        .unwrap();
    graph
        .add_edge(IoEdge::exact(2, 2, 3, IoRelation::Submits))
        .unwrap();
    assert!(
        graph
            .add_edge(IoEdge::exact(3, 3, 1, IoRelation::CompletesInto))
            .is_err()
    );

    let metrics = graph.metrics();
    assert_eq!(metrics.accounted_ns, 190);
    assert_eq!(metrics.total_ns, 200);
    assert_eq!(metrics.unaccounted_ns, 10);
    assert_eq!(metrics.critical_path, vec![1, 2, 3]);
    assert_eq!(metrics.critical_path_ns, 190);
    assert_eq!(metrics.exclusive_ns.get(&1), Some(&40));
}

#[test]
fn graph_rejects_an_edge_that_points_backward_in_time() {
    let mut graph = IoTransactionGraph::new(90);
    graph
        .add_node(node(1, IoNodeKind::BlockRequest, 500, 700))
        .unwrap();
    graph
        .add_node(node(2, IoNodeKind::FileOperation, 100, 200))
        .unwrap();
    assert!(
        graph
            .add_edge(IoEdge::exact(1, 1, 2, IoRelation::Calls))
            .is_err()
    );
}

fn identity(inode: u64) -> FileIdentity {
    FileIdentity {
        fs_device_major: 259,
        fs_device_minor: 7,
        inode,
        inode_generation: Some(3),
        mount_id: Some(42),
    }
}

#[test]
fn direct_request_origins_are_exact_multi_origin_and_suppress_heuristic_file() {
    let mut engine = AnalysisEngine::new();
    engine.ingest(StorageEvent::FileIo(FileIo {
        start_ts_ns: 90,
        end_ts_ns: 110,
        operation: IoOperation::Read,
        fd: 5,
        requested_bytes: 4096,
        completed_bytes: 4096,
        pid: 10,
        tid: 11,
        comm: "reader".into(),
        path: Some("/data/heuristic.bin".into()),
        confidence: android_ebpf_protocol::AttributionConfidence::Attributed,
        file_identity: Some(identity(999)),
        path_snapshot: None,
        offset: Some(0),
        io_mode: FileIoMode::Direct,
        node_id: None,
    }));
    engine.ingest(StorageEvent::FileIo(FileIo {
        start_ts_ns: 91,
        end_ts_ns: 520,
        operation: IoOperation::Read,
        fd: 6,
        requested_bytes: 4096,
        completed_bytes: 4096,
        pid: 99,
        tid: 100,
        comm: "reader".into(),
        path: Some("/data/exact-a.bin".into()),
        confidence: android_ebpf_protocol::AttributionConfidence::Attributed,
        file_identity: Some(FileIdentity {
            inode_generation: None,
            mount_id: None,
            ..identity(101)
        }),
        path_snapshot: Some(PathSnapshot {
            path: Some("/data/exact-a.bin".into()),
            source: PathSource::ProcFd,
            captured_ts_ns: 520,
            deleted: false,
        }),
        offset: Some(0),
        io_mode: FileIoMode::Direct,
        node_id: None,
    }));
    engine.ingest(StorageEvent::BlockIssue(BlockIssue {
        ts_ns: 112,
        request_id: 70,
        device_major: 259,
        device_minor: 0,
        sector: 4096,
        sectors: 8,
        bytes: 4096,
        operation: IoOperation::Read,
        pid: 10,
        tid: 11,
        cpu: 1,
        comm: "reader".into(),
    }));
    let warmup = engine
        .ingest(StorageEvent::BlockComplete(BlockComplete {
            ts_ns: 113,
            request_id: 70,
            device_major: 259,
            device_minor: 0,
            status: 0,
        }))
        .expect("warmup request completes");
    let _ = engine.transaction_for(&warmup);
    for (origin_id, inode) in [(501, 101), (502, 102)] {
        engine.ingest(StorageEvent::RequestOrigin(RequestOrigin {
            ts_ns: 115,
            request_id: 77,
            origin_id,
            file: identity(inode),
            path: None,
            origin: IoOrigin::File,
            operation: IoOperation::Read,
            bytes: Some(2048),
            pid: 10,
            tid: 11,
            incomplete: false,
        }));
    }
    engine.ingest(StorageEvent::BlockIssue(BlockIssue {
        ts_ns: 120,
        request_id: 77,
        device_major: 259,
        device_minor: 0,
        sector: 8192,
        sectors: 8,
        bytes: 4096,
        operation: IoOperation::Read,
        pid: 10,
        tid: 11,
        cpu: 1,
        comm: "reader".into(),
    }));
    let completed = engine
        .ingest(StorageEvent::BlockComplete(BlockComplete {
            ts_ns: 500,
            request_id: 77,
            device_major: 259,
            device_minor: 0,
            status: 0,
        }))
        .expect("request completes");

    let graph = engine.transaction_for(&completed);
    let request = graph
        .nodes
        .iter()
        .find(|node| node.kind == IoNodeKind::BlockRequest)
        .expect("request node");
    let origins = graph.file_origins_for(request.node_id);

    assert_eq!(origins.len(), 2);
    assert!(
        origins
            .iter()
            .all(|origin| origin.confidence == EdgeConfidence::Exact)
    );
    assert!(origins.iter().all(|origin| origin.file.inode != 999));
    assert_eq!(
        origins
            .iter()
            .find(|origin| origin.file.inode == 101)
            .and_then(|origin| origin.path.as_ref())
            .and_then(|snapshot| snapshot.path.as_deref()),
        Some("/data/exact-a.bin")
    );
}
