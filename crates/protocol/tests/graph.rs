use android_ebpf_protocol::{
    EdgeConfidence, FileIdentity, IoEdge, IoNode, IoNodeKind, IoOperation, IoOrigin, IoRelation,
    IoTransactionGraph, PathSnapshot, PathSource,
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
