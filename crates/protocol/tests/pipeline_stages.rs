use android_ebpf_protocol::{
    AccessPattern, AnalysisEngine, BlockComplete, BlockInsert, BlockIssue, CompletedIo,
    CorrelationConfidence, IoOperation, IoSizeClass, PipelineLayer, PipelineObservation,
    PipelinePhase, StorageEvent, build_io_pipeline,
};

fn completed() -> CompletedIo {
    CompletedIo {
        insert: Some(BlockInsert {
            ts_ns: 1_000,
            request_id: 7,
            device_major: 259,
            device_minor: 0,
            sector: 8_192,
            sectors: 8,
            bytes: 4_096,
            operation: IoOperation::Read,
        }),
        issue: BlockIssue {
            ts_ns: 1_200,
            request_id: 7,
            device_major: 259,
            device_minor: 0,
            sector: 8_192,
            sectors: 8,
            bytes: 4_096,
            operation: IoOperation::Read,
            pid: 42,
            tid: 43,
            cpu: 1,
            comm: "reader".into(),
        },
        completion: BlockComplete {
            ts_ns: 2_000,
            request_id: 7,
            device_major: 259,
            device_minor: 0,
            status: 0,
        },
        latency_ns: 800,
        queue_latency_ns: Some(200),
        device_latency_ns: 800,
        total_latency_ns: 1_000,
        queue_depth_after: 0,
        access_pattern: AccessPattern::Unknown,
        size_class: IoSizeClass::Small,
    }
}

fn span(layer: PipelineLayer, start: u64, end: u64) -> PipelineObservation {
    PipelineObservation {
        ts_ns: start,
        end_ts_ns: Some(end),
        phase: PipelinePhase::Span,
        layer,
        correlation_id: Some(7),
        stage_key: None,
        sector: Some(8_192),
        bytes: Some(4_096),
        opcode: None,
        status: None,
        pid: 42,
        tid: 43,
        name: format!("{layer:?}"),
        confidence: CorrelationConfidence::Exact,
    }
}

#[test]
fn overlapping_spans_are_accounted_as_a_union() {
    let observations = vec![
        span(PipelineLayer::Filesystem, 900, 1_500),
        span(PipelineLayer::Scsi, 1_300, 1_800),
    ];
    let pipeline = build_io_pipeline(&completed(), &observations);

    assert_eq!(pipeline.start_ts_ns, 900);
    assert_eq!(pipeline.end_ts_ns, 2_000);
    assert_eq!(pipeline.accounted_ns, 1_100);
    assert_eq!(pipeline.unaccounted_ns, 0);
    assert!(pipeline.accounted_ns <= pipeline.total_ns());
}

#[test]
fn context_only_uic_is_visible_but_not_additive() {
    let mut uic = span(PipelineLayer::UicContext, 1_400, 1_900);
    uic.confidence = CorrelationConfidence::ContextOnly;
    let pipeline = build_io_pipeline(&completed(), &[uic]);

    assert!(
        pipeline
            .spans
            .iter()
            .any(|value| value.layer == PipelineLayer::UicContext)
    );
    // Generated block queue + device spans cover the block request window only.
    assert_eq!(pipeline.accounted_ns, 1_000);
    assert_eq!(pipeline.unaccounted_ns, 0);
}

#[test]
fn exact_id_match_outranks_probable_overlap() {
    let exact = span(PipelineLayer::Ufs, 1_250, 1_850);
    let mut probable = span(PipelineLayer::Ufs, 1_260, 1_860);
    probable.correlation_id = Some(99);
    probable.confidence = CorrelationConfidence::Probable;
    let pipeline = build_io_pipeline(&completed(), &[probable, exact]);

    let ufs: Vec<_> = pipeline
        .spans
        .iter()
        .filter(|value| value.layer == PipelineLayer::Ufs)
        .collect();
    assert_eq!(ufs.len(), 1);
    assert_eq!(ufs[0].confidence, CorrelationConfidence::Exact);
}

#[test]
fn invalid_span_does_not_corrupt_accounting() {
    let invalid = span(PipelineLayer::Vfs, 1_800, 1_700);
    let pipeline = build_io_pipeline(&completed(), &[invalid]);
    assert!(
        pipeline
            .spans
            .iter()
            .all(|value| value.end_ts_ns >= value.start_ts_ns)
    );
    assert!(pipeline.accounted_ns <= pipeline.total_ns());
}

#[test]
fn exact_stage_key_pair_is_only_probable_against_a_block_request() {
    let mut lower = span(PipelineLayer::Ufs, 1_250, 1_850);
    lower.correlation_id = None;
    lower.stage_key = Some(17);
    lower.confidence = CorrelationConfidence::Exact;

    let pipeline = build_io_pipeline(&completed(), &[lower]);
    let ufs = pipeline
        .spans
        .iter()
        .find(|value| value.layer == PipelineLayer::Ufs)
        .expect("field-matched lower-layer span remains visible");
    assert_eq!(ufs.confidence, CorrelationConfidence::Probable);
}

#[test]
fn paired_command_preserves_opcode_and_completion_status() {
    let mut begin = span(PipelineLayer::Ufs, 1_250, 1_250);
    begin.end_ts_ns = None;
    begin.phase = PipelinePhase::Begin;
    begin.correlation_id = None;
    begin.stage_key = Some(17);
    begin.opcode = Some(0x28);

    let mut end = begin.clone();
    end.ts_ns = 1_850;
    end.phase = PipelinePhase::End;
    end.opcode = None;
    end.status = Some(-5);

    let mut engine = AnalysisEngine::new();
    engine.ingest(StorageEvent::Pipeline(begin));
    engine.ingest(StorageEvent::Pipeline(end));

    let paired = engine
        .pipeline_observations()
        .first()
        .expect("begin/end should form one measured command span");
    assert_eq!(paired.end_ts_ns, Some(1_850));
    assert_eq!(paired.opcode, Some(0x28));
    assert_eq!(paired.status, Some(-5));
}

#[test]
fn reused_stage_key_is_not_paired_to_the_wrong_begin() {
    let mut begin = span(PipelineLayer::Ufs, 1_200, 1_200);
    begin.end_ts_ns = None;
    begin.phase = PipelinePhase::Begin;
    begin.correlation_id = None;
    begin.stage_key = Some(17);
    let mut reused = begin.clone();
    reused.ts_ns = 1_300;
    let mut end = begin.clone();
    end.ts_ns = 1_800;
    end.phase = PipelinePhase::End;

    let mut engine = AnalysisEngine::new();
    engine.ingest(StorageEvent::Pipeline(begin));
    engine.ingest(StorageEvent::Pipeline(reused));
    engine.ingest(StorageEvent::Pipeline(end));

    assert!(engine.pipeline_observations().is_empty());
}
