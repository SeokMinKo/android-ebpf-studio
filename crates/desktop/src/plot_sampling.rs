fn operation_sample_indices(samples: &[CompletedIo], limit: usize) -> Vec<usize> {
    if samples.len() <= limit {
        return (0..samples.len()).collect();
    }
    let mut groups = BTreeMap::<IoOperation, Vec<usize>>::new();
    for (index, io) in samples.iter().enumerate() {
        groups.entry(io.issue.operation).or_default().push(index);
    }
    if limit < groups.len() {
        return evenly_sample_indices(samples.len(), limit);
    }
    let groups: Vec<_> = groups.into_values().collect();
    let mut quota: Vec<_> = groups
        .iter()
        .map(|g| (limit * g.len() / samples.len()).max(1))
        .collect();
    while quota.iter().sum::<usize>() > limit {
        let index = quota.iter().enumerate().max_by_key(|(_, v)| *v).unwrap().0;
        quota[index] -= 1;
    }
    let mut indices = Vec::with_capacity(limit);
    for (group, count) in groups.iter().zip(quota) {
        indices.extend(
            evenly_sample_indices(group.len(), count)
                .into_iter()
                .map(|i| group[i]),
        );
    }
    indices.sort_unstable();
    indices
}

#[cfg(test)]
mod sampling_regression {
    use super::*;
    use android_ebpf_protocol::*;


    #[test]
    fn dense_sampling_retains_first_and_last_observed_request() {
        for (length, limit) in [(12_388, 12_000), (12_388, 2_000), (20_000, 2)] {
            let indices = evenly_sample_indices(length, limit);
            assert_eq!(indices.len(), limit);
            assert_eq!(indices.first(), Some(&0));
            assert_eq!(indices.last(), Some(&(length - 1)), "length={length}, limit={limit}");
            assert!(indices.windows(2).all(|pair| pair[0] < pair[1]));
        }
        assert!(evenly_sample_indices(0, 0).is_empty());
        assert!(evenly_sample_indices(10, 0).is_empty());
        assert_eq!(evenly_sample_indices(10, 1), vec![0]);
    }

    #[test]
    fn incomplete_latency_is_not_a_measured_zero() {
        let mut graph = IoTransactionGraph::new(1);
        let node: IoNode = serde_json::from_value(serde_json::json!({
            "node_id":1,"kind":"ufs_command","start_ts_ns":100,
            "end_ts_ns":null,"origin":"unknown","name":"unpaired marker"
        }))
        .unwrap();
        graph.add_node(node).unwrap();
        assert_eq!(graph_kind_duration_ms(&graph, IoNodeKind::UfsCommand), None);
        graph.nodes[0].end_ts_ns = Some(100);
        assert_eq!(
            graph_kind_duration_ms(&graph, IoNodeKind::UfsCommand),
            Some(0.0)
        );
        graph.nodes[0].end_ts_ns = Some(1_000_100);
        assert_eq!(
            graph_kind_duration_ms(&graph, IoNodeKind::UfsCommand),
            Some(1.0)
        );
    }

    #[test]
    fn unpaired_pipeline_marker_preserves_missing_duration_through_graph() {
        let mut engine = AnalysisEngine::new();
        for value in [
            serde_json::json!({"kind":"block_issue","data":{"ts_ns":100,"request_id":7,"device_major":8,"device_minor":0,"sector":8,"sectors":8,"bytes":4096,"operation":"read","pid":1,"tid":1,"cpu":0,"comm":"test"}}),
            serde_json::json!({"kind":"pipeline","data":{"ts_ns":110,"layer":"ufs","phase":"instant","correlation_id":7,"name":"unpaired UFS","confidence":"exact"}}),
            serde_json::json!({"kind":"block_complete","data":{"ts_ns":200,"request_id":7,"device_major":8,"device_minor":0,"status":0}}),
        ] {
            engine.ingest(serde_json::from_value(value).unwrap());
        }
        let graph = engine.transaction_for(&engine.completed_ios()[0]);
        assert!(graph.nodes.iter().any(|n| n.kind == IoNodeKind::UfsCommand));
        assert_eq!(graph_kind_duration_ms(&graph, IoNodeKind::UfsCommand), None);
    }

    #[test]
    fn alternating_operations_survive_explorer_downsampling() {
        let mut app = StudioApp::default();
        for id in 1..=20_000 {
            app.analyzer.ingest(StorageEvent::BlockIssue(BlockIssue {
                ts_ns: id * 1000,
                request_id: id,
                device_major: 8,
                device_minor: 0,
                sector: id * 8,
                sectors: 8,
                bytes: 4096,
                operation: if id % 2 == 0 {
                    IoOperation::Write
                } else {
                    IoOperation::Read
                },
                pid: 1,
                tid: 1,
                cpu: 0,
                comm: "alternating".into(),
            }));
            app.analyzer
                .ingest(StorageEvent::BlockComplete(BlockComplete {
                    ts_ns: id * 1000 + 10,
                    request_id: id,
                    device_major: 8,
                    device_minor: 0,
                    status: 0,
                }));
        }
        app.x_axis = AxisMetric::TimeMs;
        app.y_axis = AxisMetric::Sector;
        app.group_by = GroupBy::Direction;
        app.rebuild_explorer_view();
        let view = app.explorer_view.unwrap();
        assert!(
            view.groups
                .iter()
                .any(|(name, points)| name == "Read" && !points.is_empty())
        );
        assert!(
            view.groups
                .iter()
                .any(|(name, points)| name == "Write" && !points.is_empty()),
            "Periodic sampling must not erase Write"
        );
        assert!(view.displayed <= MAX_GRAPH_EXPLORER_POINTS);
    }
}
