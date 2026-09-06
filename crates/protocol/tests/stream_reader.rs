use android_ebpf_protocol::{SessionReader, WireRecord};
use std::io::Cursor;

#[test]
fn oversized_and_invalid_utf8_records_are_bounded_and_do_not_hide_later_records() {
    let footer=br#"{"record":"footer","schema_version":5,"events_seen":0,"events_persisted":0,"events_dropped":0,"events_rejected":0,"graceful":true}"#;
    let mut input = vec![b'x'; 2_000_000];
    input.extend_from_slice(footer);
    input.push(b'\n');
    input.extend_from_slice(&[0xff, b'\n']);
    input.extend_from_slice(footer);
    input.push(b'\n');
    let mut count = 0;
    let (lines, rejected) = SessionReader::new(200)
        .visit(Cursor::new(input), |record| {
            assert!(matches!(record, WireRecord::Footer { .. }));
            count += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!((lines, rejected, count), (3, 2, 1));
}

#[test]
fn footer_arithmetic_does_not_prove_missing_events_exist() {
    let missing=br#"{"record":"footer","schema_version":5,"events_seen":3,"events_persisted":3,"events_dropped":0,"events_rejected":0,"graceful":true}"#;
    let loaded = SessionReader::default().read(Cursor::new(missing)).unwrap();
    assert_eq!(loaded.integrity_ok, Some(false));
    assert_eq!(loaded.accepted_events, 0);
}
