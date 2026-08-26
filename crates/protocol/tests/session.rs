use std::io::Cursor;

use android_ebpf_protocol::{
    BlockIssue, IoOperation, SCHEMA_VERSION, SessionReader, StorageEvent, WireRecord,
};

#[test]
fn session_reader_keeps_valid_records_and_counts_rejected_lines() {
    let event = WireRecord::Event {
        schema_version: SCHEMA_VERSION,
        sequence: 1,
        event: StorageEvent::BlockIssue(BlockIssue {
            ts_ns: 10,
            request_id: 7,
            device_major: 259,
            device_minor: 0,
            sector: 16,
            sectors: 8,
            bytes: 4096,
            operation: IoOperation::Write,
            pid: 1,
            tid: 1,
            cpu: 0,
            comm: "writer".into(),
        }),
    };
    let valid = serde_json::to_string(&event).unwrap();
    let input = format!("{valid}\nnot-json\n{{\"record\":\"future_kind\"}}\n");

    let loaded = SessionReader::default()
        .read(Cursor::new(input))
        .expect("I/O succeeds even when individual lines are bad");

    assert_eq!(loaded.events.len(), 1);
    assert_eq!(loaded.rejected_lines, 2);
    assert_eq!(loaded.total_lines, 3);
}

#[test]
fn unknown_json_fields_are_forward_compatible() {
    let input = concat!(
        "{\"record\":\"health\",\"schema_version\":1,",
        "\"emitted_events\":2,\"kernel_drops\":0,\"userspace_drops\":0,",
        "\"future_field\":true}\n"
    );

    let loaded = SessionReader::default().read(Cursor::new(input)).unwrap();
    assert_eq!(loaded.health.len(), 1);
    assert_eq!(loaded.rejected_lines, 0);
}
