use android_ebpf_protocol::{
    AnalysisEngine, SCHEMA_VERSION, SchedulerIoWait, StorageEvent, WireRecord, write_record,
};
use android_ebpf_studio::session;

#[test]
fn scheduler_retention_is_explicit_and_original_window_recovers_old_events() {
    let path = std::env::temp_dir().join(format!(
        "scheduler-retention-{}.ndjson",
        uuid::Uuid::new_v4()
    ));
    let mut file = std::io::BufWriter::new(std::fs::File::create(&path).unwrap());
    let mut engine = AnalysisEngine::new();
    for i in 0..100_005u64 {
        let event = StorageEvent::SchedulerIoWait(SchedulerIoWait {
            ts_ns: 1_000_000 + i * 1000,
            delay_ns: i,
            tid: 42,
            pid: None,
            comm: "worker".into(),
            cpu: Some(0),
            source: "fixture".into(),
        });
        write_record(
            &mut file,
            &WireRecord::Event {
                schema_version: SCHEMA_VERSION,
                sequence: i + 1,
                event: event.clone(),
            },
        )
        .unwrap();
        engine.ingest(event);
    }
    drop(file);
    assert_eq!(engine.scheduler_waits().len(), 90_005);
    assert_eq!(engine.scheduler_waits_dropped(), 10_000);
    assert_eq!(engine.scheduler_start_ns(), Some(1_000_000));
    assert_eq!(engine.session_start_ns(), None);
    assert_eq!(engine.summary().completed_ios, 0);
    let filtered = engine.select_completed(|_| false);
    assert_eq!(filtered.scheduler_waits_dropped(), 10_000);
    let window = session::load_analysis_window(&path, Some((1_000_000, 1_005_000)), None).unwrap();
    assert_eq!(
        window
            .engine
            .scheduler_waits()
            .iter()
            .map(|w| w.delay_ns)
            .collect::<Vec<_>>(),
        [0, 1, 2, 3, 4, 5]
    );
    assert_eq!(window.engine.scheduler_waits_dropped(), 0);
    let error = session::load_analysis_window(&path, Some((1_000_000, 200_000_000)), None)
        .expect_err("oversized selected window must not silently evict events");
    assert!(error.to_string().contains("100,000 scheduler wait events"));
    std::fs::remove_file(path).unwrap();
}
