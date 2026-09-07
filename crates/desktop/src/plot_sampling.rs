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


// Coordinates are measured before sampling. Selection still uses the complete cohort.
fn shape_sample_indices(points: &[ExplorerPoint], limit: usize) -> Vec<usize> {
    if points.len() <= limit { return (0..points.len()).collect(); }
    if points.is_empty() { return Vec::new(); }
    let mut keep = std::collections::BTreeSet::new();
    // Preserve first/last and both-axis extrema within each chronological bucket.
    let buckets = (limit / 6).max(1).min(points.len());
    for bucket in 0..buckets {
        let start = bucket * points.len() / buckets;
        let end = (bucket + 1) * points.len() / buckets;
        keep.insert(start); keep.insert(end - 1);
        for axis in 0..2 {
            keep.insert((start..end).min_by(|&a,&b|points[a].coordinates[axis].total_cmp(&points[b].coordinates[axis])).unwrap());
            keep.insert((start..end).max_by(|&a,&b|points[a].coordinates[axis].total_cmp(&points[b].coordinates[axis])).unwrap());
        }
    }
    // Preserve both sides of sparse coordinate gaps. A gap is larger than eight
    // ordinary positive spacings and two target sampling cells on that axis.
    for axis in 0..2 {
        let mut sorted: Vec<_> = (0..points.len()).collect();
        sorted.sort_by(|&a,&b|points[a].coordinates[axis].total_cmp(&points[b].coordinates[axis]));
        let mut deltas: Vec<_> = sorted.windows(2).map(|w|points[w[1]].coordinates[axis]-points[w[0]].coordinates[axis]).filter(|&d|d>0.0).collect();
        if deltas.is_empty() { continue; }
        deltas.sort_by(f64::total_cmp);
        let span = points[*sorted.last().unwrap()].coordinates[axis] - points[sorted[0]].coordinates[axis];
        let threshold = (8.0 * deltas[deltas.len()/2]).max(2.0 * span / limit.max(1) as f64);
        for pair in sorted.windows(2) {
            if points[pair[1]].coordinates[axis]-points[pair[0]].coordinates[axis] > threshold { keep.extend(pair); }
        }
    }
    // The target is soft: never discard a mandatory feature just to hit a cap.
    if keep.len() < limit {
        let remaining: Vec<_> = (0..points.len()).filter(|i|!keep.contains(i)).collect();
        for index in evenly_sample_indices(remaining.len(), limit-keep.len()) { keep.insert(remaining[index]); }
    }
    keep.into_iter().collect()
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
                .ingest(StorageEvent::BlockComplete(BlockComplete {cpu:None,
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

#[cfg(test)]
mod plotted_extrema_regression {
    use super::*;
    use android_ebpf_protocol::*;
    #[test]
    fn lba_retains_penultimate_peak_and_sparse_gap_boundary() {
        let mut app = StudioApp::default();
        for index in 0..2001u64 {
            let ts = (index + 1) * 1000 + if index >= 1999 { 10_000_000 } else { 0 };
            let sector = if index == 1999 { 2_000_000 } else { index * 8 };
            app.analyzer.ingest(StorageEvent::BlockIssue(BlockIssue {
                ts_ns: ts, request_id:index+1,device_major:8,device_minor:0,sector,sectors:8,bytes:4096,operation:IoOperation::Read,pid:1,tid:1,cpu:0,comm:"peak-gap".into(),
            }));
            app.analyzer.ingest(StorageEvent::BlockComplete(BlockComplete {cpu:None,ts_ns:ts+500,request_id:index+1,device_major:8,device_minor:0,status:0}));
        }
        app.rebuild_explorer_view();
        let view = app.explorer_view.as_ref().unwrap();
        let points: Vec<_> = view.groups.iter().flat_map(|(_,p)|p).collect();
        assert!(points.iter().any(|p|p.coordinates[1] == 1024.0), "raw interior max 1024 MB must be rendered");
        for request in [1,1999,2000,2001] {
            assert!(points.iter().any(|p|p.request.0 == request), "endpoint/gap boundary {request} disappeared");
        }
        assert!(points.iter().all(|p|p.coordinates[1]==1024.0 || p.coordinates[1] == (p.request.0-1) as f64 * 8.0 * 512.0 / 1_000_000.0));
    }
}
