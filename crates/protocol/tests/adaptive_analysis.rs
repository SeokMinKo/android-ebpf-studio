use std::io::Cursor;

use android_ebpf_protocol::{
    AggregateCounters, AggregateSnapshot, CaptureConfig, CaptureControlAck,
    CaptureFilter, CaptureMode, CaptureState, ControlOutcome, DetailPolicy,
    HeavyHitterDimension, HeavyHitterEntry, HeavyHitterMetric, HeavyHitterSnapshot,
    Histogram, HistogramMetric, SegmentRecord, SessionReader, StackFingerprintRecord,
    StackKind, TriggerRecord, WireRecord, write_record,
};

#[test]
fn filter_config_rejects_partial_or_unbounded_input() {
    let mut config = CaptureConfig {
        generation: 2,
        mode: CaptureMode::Balanced,
        filter: CaptureFilter {
            match_all: false,
            pids: vec![10, 10],
            ..CaptureFilter::default()
        },
        detail: DetailPolicy::default(),
        trigger: None,
    };
    assert!(config.validate(64).is_err());

    config.filter.pids = (0..65).collect();
    assert!(config.validate(64).is_err());

    config.filter.pids = vec![10, 11];
    config.filter.min_bytes = Some(4096);
    config.filter.max_bytes = Some(1024);
    assert!(config.validate(64).is_err());

    config.filter.max_bytes = Some(8192);
    assert!(config.validate(64).is_ok());
}

#[test]
fn histogram_reports_an_approximate_bucket_range() {
    let mut histogram = Histogram::new(vec![100, 1_000, 10_000]).unwrap();
    for value in [50, 100, 101, 999, 1_000, 2_000, 20_000] {
        histogram.record(value);
    }
    assert_eq!(histogram.total_count(), 7);
    assert_eq!(histogram.percentile_range(50), Some((101, Some(1_000))));
    assert_eq!(histogram.percentile_range(100), Some((10_001, None)));
}

#[test]
fn protocol_v5_round_trips_analysis_records_and_keeps_v4_readable() {
    let aggregate = AggregateSnapshot {
        session_id: "session-a".into(),
        epoch: 7,
        config_generation: 2,
        start_ts_ns: 1_000,
        end_ts_ns: 2_000,
        counters: AggregateCounters {
            observed: 100,
            detail_emitted: 3,
            suppressed_fast: 97,
            ..AggregateCounters::default()
        },
        histograms: vec![(
            HistogramMetric::TotalLatency,
            Histogram {
                boundaries: vec![100, 1_000],
                counts: vec![10, 80, 10],
            },
        )],
    };
    let records = vec![
        WireRecord::Control {
            schema_version: 5,
            acknowledgement: CaptureControlAck {
                requested_generation: 2,
                active_generation: 2,
                outcome: ControlOutcome::Applied,
                reason: None,
            },
        },
        WireRecord::Aggregate {
            schema_version: 5,
            snapshot: aggregate,
        },
        WireRecord::HeavyHitters {
            schema_version: 5,
            snapshot: HeavyHitterSnapshot {
                epoch: 7,
                dimension: HeavyHitterDimension::Process,
                metric: HeavyHitterMetric::CumulativeLatency,
                candidate_capacity: 64,
                evicted_keys: 4,
                covered_metric: 90,
                total_metric: 100,
                entries: vec![HeavyHitterEntry {
                    key: "camera:123".into(),
                    count: 10,
                    bytes: 40960,
                    cumulative_latency_ns: 5_000,
                    max_latency_ns: 1_000,
                    confidence: None,
                }],
            },
        },
        WireRecord::Trigger {
            schema_version: 5,
            trigger: TriggerRecord {
                ts_ns: 2_000,
                from: CaptureState::Armed,
                to: CaptureState::Deep,
                rule: "p99_total".into(),
                observed: 8_000_000,
                threshold: 5_000_000,
                consecutive_windows: 3,
                config_generation: 2,
                reason: "threshold_exceeded".into(),
            },
        },
        WireRecord::Segment {
            schema_version: 5,
            segment: SegmentRecord {
                segment_id: 9,
                trigger_ts_ns: 2_000,
                requested_start_ts_ns: 500,
                retained_start_ts_ns: 750,
                end_ts_ns: 4_000,
                retained_bytes: 4096,
                evicted_records: 2,
            },
        },
        WireRecord::StackFingerprint {
            schema_version: 5,
            fingerprint: StackFingerprintRecord {
                ts_ns: 2_100,
                transaction_id: Some(10),
                kind: StackKind::User,
                opaque_stack_id: 77,
                frame_count: 4,
                symbolized: false,
                sample_count: 1,
                tail_count: 1,
                cumulative_latency_ns: 8_000_000,
            },
        },
    ];
    let mut bytes = Vec::new();
    for record in &records {
        write_record(&mut bytes, record).unwrap();
    }
    bytes.extend_from_slice(
        br#"{"record":"health","schema_version":4,"emitted_events":0,"kernel_drops":null,"userspace_drops":0}"#,
    );
    bytes.push(b'\n');

    let loaded = SessionReader::default().read(Cursor::new(bytes)).unwrap();
    assert_eq!(loaded.controls.len(), 1);
    assert_eq!(loaded.aggregates.len(), 1);
    assert_eq!(loaded.heavy_hitters.len(), 1);
    assert_eq!(loaded.triggers.len(), 1);
    assert_eq!(loaded.segments.len(), 1);
    assert_eq!(loaded.stack_fingerprints.len(), 1);
    assert_eq!(loaded.health.len(), 1);
    assert_eq!(loaded.rejected_lines, 0);
}
