use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use android_ebpf_protocol::{
    AggregateCounters, AggregateSnapshot, AttributionConfidence, BlockComplete, BlockInsert,
    BlockIssue, CorrelationConfidence, FileIo, HeavyHitterDimension, HeavyHitterEntry,
    HeavyHitterMetric, HeavyHitterSnapshot, Histogram, HistogramMetric, IoOperation, PipelineLayer,
    PipelineObservation, PipelinePhase, SCHEMA_VERSION, SegmentRecord, StackFingerprintRecord,
    StackKind, StorageEvent, TriggerRecord, CaptureState, WireRecord,
};
use crossbeam_channel::Sender;

use crate::capture::HostMessage;

pub fn start(tx: Sender<HostMessage>, stop: Arc<AtomicBool>) {
    thread::spawn(move || {
        let hello = WireRecord::Hello {
            schema_version: SCHEMA_VERSION,
            agent_version: env!("CARGO_PKG_VERSION").into(),
            boot_id: "simulated-boot".into(),
            kernel_release: "simulated-android".into(),
        };
        tx.send(HostMessage::Record(hello)).ok();
        tx.send(HostMessage::Status(
            "Running deterministic simulator".into(),
        ))
        .ok();
        let mut ts_ns = 0_u64;
        let mut sequence = 1_u64;
        let mut record_sequence = 1_u64;
        let mut read_sector = 1_024_u64;
        let mut write_sector = 65_536_u64;
        let mut total_bytes = 0_u64;
        let mut cumulative_latency_ns = 0_u64;
        let mut latency_histogram = Histogram::new(vec![
            100_000, 250_000, 500_000, 1_000_000, 2_000_000, 5_000_000, 10_000_000,
        ])
        .expect("simulator histogram boundaries are valid");
        while !stop.load(Ordering::Acquire) {
            let bytes = if sequence.is_multiple_of(8) {
                131_072
            } else {
                4_096
            };
            let operation = if sequence.is_multiple_of(3) {
                IoOperation::Write
            } else {
                IoOperation::Read
            };
            let stream_sector = if operation == IoOperation::Read {
                &mut read_sector
            } else {
                &mut write_sector
            };
            if sequence.is_multiple_of(7) {
                *stream_sector += 8_192;
            }
            let sector = *stream_sector;
            *stream_sector += (bytes / 512) as u64;
            let insert_ts = ts_ns;
            let issue_ts = ts_ns + 100_000 + (sequence % 4) * 50_000;
            let latency_ns = 200_000 + (sequence % 20) * 100_000;
            let completion_ts = issue_ts + latency_ns;
            total_bytes = total_bytes.saturating_add(bytes as u64);
            let total_latency_ns = completion_ts.saturating_sub(insert_ts);
            cumulative_latency_ns = cumulative_latency_ns.saturating_add(total_latency_ns);
            latency_histogram.record(total_latency_ns);
            let pipeline_spans = [
                (
                    PipelineLayer::Syscall,
                    insert_ts.saturating_sub(400_000),
                    completion_ts + 80_000,
                    "read/write syscall",
                    CorrelationConfidence::Exact,
                ),
                (
                    PipelineLayer::Vfs,
                    insert_ts.saturating_sub(320_000),
                    issue_ts.saturating_sub(80_000),
                    "vfs_iter_read/write",
                    CorrelationConfidence::Exact,
                ),
                (
                    PipelineLayer::Filesystem,
                    insert_ts.saturating_sub(240_000),
                    issue_ts.saturating_sub(100_000),
                    "f2fs/ext4 file operation",
                    CorrelationConfidence::Exact,
                ),
                (
                    if operation == IoOperation::Read {
                        PipelineLayer::PageCache
                    } else {
                        PipelineLayer::Writeback
                    },
                    insert_ts.saturating_sub(180_000),
                    issue_ts.saturating_sub(110_000),
                    if operation == IoOperation::Read {
                        "page-cache miss / readahead"
                    } else {
                        "buffered writeback"
                    },
                    CorrelationConfidence::Probable,
                ),
                (
                    PipelineLayer::Bio,
                    issue_ts.saturating_sub(100_000),
                    issue_ts.saturating_sub(40_000),
                    "bio submit",
                    CorrelationConfidence::Probable,
                ),
                (
                    PipelineLayer::Scsi,
                    issue_ts + 30_000,
                    completion_ts.saturating_sub(20_000),
                    "SCSI command",
                    CorrelationConfidence::Probable,
                ),
                (
                    PipelineLayer::Ufs,
                    issue_ts + 60_000,
                    completion_ts.saturating_sub(40_000),
                    "UFS command",
                    CorrelationConfidence::Probable,
                ),
                (
                    PipelineLayer::UicContext,
                    issue_ts + 10_000,
                    issue_ts + 10_000,
                    "UIC link active",
                    CorrelationConfidence::ContextOnly,
                ),
            ];
            for (layer, start_ts_ns, end_ts_ns, name, confidence) in pipeline_spans {
                let event = StorageEvent::Pipeline(PipelineObservation {
                    ts_ns: start_ts_ns,
                    end_ts_ns: Some(end_ts_ns.max(start_ts_ns)),
                    phase: if layer == PipelineLayer::UicContext {
                        PipelinePhase::Instant
                    } else {
                        PipelinePhase::Span
                    },
                    layer,
                    correlation_id: Some(sequence),
                    stage_key: None,
                    sector: Some(sector),
                    bytes: Some(bytes),
                    opcode: None,
                    status: None,
                    pid: 4242,
                    tid: 4242,
                    name: name.into(),
                    confidence,
                });
                tx.send(HostMessage::Record(WireRecord::Event {
                    schema_version: SCHEMA_VERSION,
                    sequence: record_sequence,
                    event,
                }))
                .ok();
                record_sequence += 1;
            }
            let insert = StorageEvent::BlockInsert(BlockInsert {
                ts_ns: insert_ts,
                request_id: sequence,
                device_major: 259,
                device_minor: 0,
                sector,
                sectors: bytes / 512,
                bytes,
                operation,
            });
            tx.send(HostMessage::Record(WireRecord::Event {
                schema_version: SCHEMA_VERSION,
                sequence: record_sequence,
                event: insert,
            }))
            .ok();
            record_sequence += 1;
            let issue = StorageEvent::BlockIssue(BlockIssue {
                ts_ns: issue_ts,
                request_id: sequence,
                device_major: 259,
                device_minor: 0,
                sector,
                sectors: bytes / 512,
                bytes,
                operation,
                pid: 4242,
                tid: 4242,
                cpu: (sequence % 8) as u32,
                comm: "fio-sim".into(),
            });
            tx.send(HostMessage::Record(WireRecord::Event {
                schema_version: SCHEMA_VERSION,
                sequence: record_sequence,
                event: issue,
            }))
            .ok();
            record_sequence += 1;
            let completion = StorageEvent::BlockComplete(BlockComplete {
                ts_ns: completion_ts,
                request_id: sequence,
                device_major: 259,
                device_minor: 0,
                status: 0,
            });
            tx.send(HostMessage::Record(WireRecord::Event {
                schema_version: SCHEMA_VERSION,
                sequence: record_sequence,
                event: completion,
            }))
            .ok();
            record_sequence += 1;
            if sequence.is_multiple_of(4) {
                let file = StorageEvent::FileIo(FileIo {
                    start_ts_ns: insert_ts.saturating_sub(50_000),
                    end_ts_ns: completion_ts + 50_000,
                    operation,
                    fd: 7,
                    requested_bytes: bytes as u64,
                    completed_bytes: bytes as i64,
                    pid: 4242,
                    tid: 4242,
                    comm: "fio-sim".into(),
                    path: Some(if operation == IoOperation::Read {
                        "/data/local/tmp/read.bin".into()
                    } else {
                        "/data/local/tmp/write.bin".into()
                    }),
                    confidence: AttributionConfidence::Attributed,
                    file_identity: Some(android_ebpf_protocol::FileIdentity {
                        fs_device_major: 259,
                        fs_device_minor: 7,
                        inode: 10_000 + sequence,
                        inode_generation: None,
                        mount_id: Some(1),
                    }),
                    path_snapshot: None,
                    offset: Some(sector.saturating_mul(512)),
                    io_mode: android_ebpf_protocol::FileIoMode::Buffered,
                    node_id: Some(1_000_000 + sequence),
                });
                tx.send(HostMessage::Record(WireRecord::Event {
                    schema_version: SCHEMA_VERSION,
                    sequence: record_sequence,
                    event: file,
                }))
                .ok();
                record_sequence += 1;
            }
            if sequence.is_multiple_of(200) {
                tx.send(HostMessage::Record(WireRecord::Aggregate {
                    schema_version: SCHEMA_VERSION,
                    snapshot: AggregateSnapshot {
                        session_id: "simulator".into(),
                        epoch: sequence / 200,
                        config_generation: 1,
                        start_ts_ns: 0,
                        end_ts_ns: completion_ts,
                        counters: AggregateCounters {
                            observed: sequence,
                            bytes: total_bytes,
                            filter_passed: sequence,
                            detail_emitted: sequence,
                            ..AggregateCounters::default()
                        },
                        histograms: vec![(
                            HistogramMetric::TotalLatency,
                            latency_histogram.clone(),
                        )],
                    },
                }))
                .ok();
                tx.send(HostMessage::Record(WireRecord::HeavyHitters {
                    schema_version: SCHEMA_VERSION,
                    snapshot: HeavyHitterSnapshot {
                        epoch: sequence / 200,
                        dimension: HeavyHitterDimension::Process,
                        metric: HeavyHitterMetric::CumulativeLatency,
                        candidate_capacity: 64,
                        evicted_keys: 0,
                        covered_metric: cumulative_latency_ns,
                        total_metric: cumulative_latency_ns,
                        entries: vec![HeavyHitterEntry {
                            key: "fio-sim (4242)".into(),
                            count: sequence,
                            bytes: total_bytes,
                            cumulative_latency_ns,
                            max_latency_ns: total_latency_ns,
                            confidence: None,
                        }],
                    },
                }))
                .ok();
            }
            if sequence == 200 {
                tx.send(HostMessage::Record(WireRecord::Trigger {
                    schema_version: SCHEMA_VERSION,
                    trigger: TriggerRecord {
                        ts_ns: completion_ts,
                        from: CaptureState::Armed,
                        to: CaptureState::Deep,
                        rule: "p99_total_latency".into(),
                        observed: total_latency_ns,
                        threshold: 1_000_000,
                        consecutive_windows: 3,
                        config_generation: 2,
                        reason: "simulated_threshold".into(),
                    },
                }))
                .ok();
                tx.send(HostMessage::Record(WireRecord::StackFingerprint {
                    schema_version: SCHEMA_VERSION,
                    fingerprint: StackFingerprintRecord {
                        ts_ns: completion_ts,
                        transaction_id: Some(sequence),
                        kind: StackKind::Kernel,
                        opaque_stack_id: 0x51a_cafe,
                        frame_count: 12,
                        symbolized: false,
                        sample_count: 7,
                        tail_count: 5,
                        cumulative_latency_ns: total_latency_ns.saturating_mul(7),
                    },
                }))
                .ok();
                tx.send(HostMessage::Record(WireRecord::Segment {
                    schema_version: SCHEMA_VERSION,
                    segment: SegmentRecord {
                        segment_id: 1,
                        trigger_ts_ns: completion_ts,
                        requested_start_ts_ns: completion_ts.saturating_sub(3_000_000_000),
                        retained_start_ts_ns: completion_ts.saturating_sub(1_000_000_000),
                        end_ts_ns: completion_ts.saturating_add(10_000_000_000),
                        retained_bytes: 4_194_304,
                        evicted_records: 17,
                    },
                }))
                .ok();
            }
            sequence += 1;
            ts_ns += 5_000_000;
            thread::sleep(Duration::from_millis(5));
        }
        let events = record_sequence.saturating_sub(1);
        tx.send(HostMessage::Record(WireRecord::Footer {
            schema_version: SCHEMA_VERSION,
            events_seen: events,
            events_persisted: events,
            events_dropped: 0,
            events_rejected: 0,
            graceful: Some(true),
        }))
        .ok();
        tx.send(HostMessage::Ended(Ok(()))).ok();
    });
}
