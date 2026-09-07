use android_ebpf_protocol::*;

fn issue(id: u64, ts: u64) -> StorageEvent {
    StorageEvent::BlockIssue(BlockIssue {
        ts_ns: ts,
        request_id: id,
        device_major: 8,
        device_minor: 0,
        sector: id * 8,
        sectors: 8,
        bytes: 4096,
        operation: IoOperation::Read,
        pid: 7,
        tid: 7,
        cpu: 0,
        comm: "fixture".into(),
    })
}
fn complete(id: u64, ts: u64) -> StorageEvent {
    StorageEvent::BlockComplete(BlockComplete {
        cpu: None,
        ts_ns: ts,
        request_id: id,
        device_major: 8,
        device_minor: 0,
        status: 0,
    })
}
fn origin(
    id: u64,
    origin_id: u64,
    ts: u64,
    path: Option<&str>,
    confidence: EdgeConfidence,
) -> StorageEvent {
    StorageEvent::RequestOrigin(RequestOrigin {
        ts_ns: ts,
        request_id: id,
        origin_id,
        file: FileIdentity {
            fs_device_major: 8,
            fs_device_minor: 0,
            inode: origin_id,
            inode_generation: Some(1),
            mount_id: Some(1),
        },
        path: path.map(|path| PathSnapshot {
            path: Some(path.into()),
            source: PathSource::ProcFd,
            captured_ts_ns: ts,
            deleted: false,
        }),
        origin: IoOrigin::File,
        operation: IoOperation::Read,
        bytes: Some(4096),
        pid: 7,
        tid: 7,
        file_origin_confidence: confidence,
        request_lifetime_confidence: EdgeConfidence::Exact,
        incomplete: false,
    })
}

#[test]
fn full_coverage_keeps_late_origins_and_old_evidence_beyond_both_retention_limits() {
    let mut coverage = FilePathCoverageEngine::default();
    let mut detail = AnalysisEngine::new();
    for id in 1..=100_001 {
        let ts = id * 1_000_000_000;
        for event in [issue(id, ts), complete(id, ts + 20)] {
            coverage.ingest(&event);
            detail.ingest(event);
        }
        // Fill both node and edge retention limits. The earliest request's
        // evidence arrives only after its completion was evicted from detail.
        if id > 1 {
            coverage.ingest(&origin(
                id,
                id,
                ts + 10,
                Some("/data/known"),
                EdgeConfidence::Exact,
            ));
        }
    }
    coverage.ingest(&origin(
        1,
        1,
        1_000_000_010,
        Some("/data/late"),
        EdgeConfidence::Probable,
    ));
    assert_eq!(detail.completed_ios().len(), 90_001);
    let result = coverage.finish();
    assert_eq!(result.completion_records(), 100_001);
    assert_eq!(result.exact.count, 100_000);
    assert_eq!(result.probable.count, 1);
    assert_eq!(result.unresolved.count, 0);
    assert_eq!(result.known_bytes(), 100_001 * 4096);
    assert_eq!(detail.summary().completed_ios, 100_001);
    assert_eq!(
        FilePathCoverageEngine::default()
            .finish()
            .completion_records(),
        0
    );
}

#[test]
fn pathless_identity_and_mixed_candidates_remain_unresolved_and_unpaired_is_in_denominator() {
    let mut engine = FilePathCoverageEngine::default();
    for id in 1..=4 {
        engine.ingest(&issue(id, 100));
        engine.ingest(&complete(id, 200));
    }
    engine.ingest(&origin(1, 11, 150, None, EdgeConfidence::Exact));
    engine.ingest(&origin(2, 21, 150, Some("/data/a"), EdgeConfidence::Exact));
    engine.ingest(&origin(2, 22, 150, None, EdgeConfidence::Probable));
    engine.ingest(&origin(3, 31, 150, Some("/data/a"), EdgeConfidence::Exact));
    engine.ingest(&origin(
        3,
        32,
        150,
        Some("/data/b"),
        EdgeConfidence::ProbableAsync,
    ));
    engine.ingest(&complete(999, 201));
    engine.ingest(&issue(555, 300));
    let result = engine.finish();
    assert_eq!(result.completion_records(), 5);
    assert_eq!(result.exact.count, 0);
    assert_eq!(result.probable.count, 1);
    assert_eq!(result.unresolved.count, 4);
    assert_eq!(result.missing_path, 2);
    assert_eq!(result.no_origin, 1);
    assert_eq!(result.unmatched_completions, 1);
    assert_eq!(result.issue_events_without_completion, 1);
    assert_eq!(result.multi_origin.count, 2);
    assert_eq!(result.known_bytes(), 4 * 4096);
}

#[test]
fn reused_request_id_does_not_take_an_earlier_lifetimes_path() {
    let mut engine = FilePathCoverageEngine::default();
    engine.ingest(&issue(1, 100));
    engine.ingest(&complete(1, 200));
    engine.ingest(&issue(1, 300));
    engine.ingest(&complete(1, 400));
    engine.ingest(&origin(1, 1, 150, Some("/data/old"), EdgeConfidence::Exact));
    let result = engine.finish();
    assert_eq!(result.exact.count, 1);
    assert_eq!(result.unresolved.count, 1);
    assert_eq!(result.no_origin, 1);
}

#[test]
fn cancellation_during_final_attribution_returns_no_partial_success() {
    let mut engine = FilePathCoverageEngine::default();
    engine.ingest(&issue(1, 100));
    engine.ingest(&complete(1, 200));
    assert_eq!(engine.finish_with(|| Err("cancelled")), Err("cancelled"));
}

#[test]
fn incomplete_origin_set_cannot_report_full_path_resolution() {
    let mut engine = FilePathCoverageEngine::default();
    engine.ingest(&issue(1, 100));
    engine.ingest(&complete(1, 200));
    let StorageEvent::RequestOrigin(mut partial) =
        origin(1, 1, 150, Some("/data/known"), EdgeConfidence::Exact)
    else {
        unreachable!()
    };
    partial.incomplete = true;
    engine.ingest(&StorageEvent::RequestOrigin(partial));
    let result = engine.finish();
    assert_eq!(result.exact.count, 0);
    assert_eq!(result.unresolved.count, 1);
    assert_eq!(result.incomplete_origin_set, 1);
}

#[test]
fn context_candidate_is_not_upgraded_by_a_probable_neighbor() {
    let StorageEvent::RequestOrigin(a) =
        origin(1, 1, 150, Some("/data/a"), EdgeConfidence::Probable)
    else {
        unreachable!()
    };
    let mut candidates = vec![FileOriginView {
        file: a.file,
        path: a.path,
        confidence: EdgeConfidence::Probable,
        incomplete: false,
    }];
    assert_eq!(
        FilePathConfidence::from_origins(&candidates),
        FilePathConfidence::Probable
    );
    let mut context = candidates[0].clone();
    context.file.inode += 1;
    context.confidence = EdgeConfidence::ContextOnly;
    candidates.push(context);
    assert_eq!(
        FilePathConfidence::from_origins(&candidates),
        FilePathConfidence::Unresolved
    );
}
