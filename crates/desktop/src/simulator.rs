use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use android_ebpf_protocol::{
    AttributionConfidence, BlockComplete, BlockInsert, BlockIssue, FileIo, IoOperation,
    SCHEMA_VERSION, StorageEvent, WireRecord,
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
            let latency_ns = 200_000 + (sequence % 20) * 100_000;
            let completion = StorageEvent::BlockComplete(BlockComplete {
                ts_ns: issue_ts + latency_ns,
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
                    end_ts_ns: issue_ts + latency_ns + 50_000,
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
                });
                tx.send(HostMessage::Record(WireRecord::Event {
                    schema_version: SCHEMA_VERSION,
                    sequence: record_sequence,
                    event: file,
                }))
                .ok();
                record_sequence += 1;
            }
            sequence += 1;
            ts_ns += 5_000_000;
            thread::sleep(Duration::from_millis(5));
        }
        tx.send(HostMessage::Ended(Ok(()))).ok();
    });
}
