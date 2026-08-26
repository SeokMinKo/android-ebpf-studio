use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use android_ebpf_protocol::{
    BlockComplete, BlockIssue, IoOperation, SCHEMA_VERSION, StorageEvent, WireRecord,
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
            let sector = if sequence.is_multiple_of(11) {
                sequence * 4096
            } else {
                sequence * 8
            };
            let issue = StorageEvent::BlockIssue(BlockIssue {
                ts_ns,
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
                sequence: sequence * 2 - 1,
                event: issue,
            }))
            .ok();
            let latency_ns = 200_000 + (sequence % 20) * 100_000;
            let completion = StorageEvent::BlockComplete(BlockComplete {
                ts_ns: ts_ns + latency_ns,
                request_id: sequence,
                device_major: 259,
                device_minor: 0,
                status: 0,
            });
            tx.send(HostMessage::Record(WireRecord::Event {
                schema_version: SCHEMA_VERSION,
                sequence: sequence * 2,
                event: completion,
            }))
            .ok();
            sequence += 1;
            ts_ns += 5_000_000;
            thread::sleep(Duration::from_millis(5));
        }
        tx.send(HostMessage::Ended(Ok(()))).ok();
    });
}
