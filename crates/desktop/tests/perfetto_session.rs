use android_ebpf_protocol::{StorageEvent, WireRecord};
use android_ebpf_studio::{perfetto, perfetto_session::*, session};
use std::path::PathBuf;

fn vi(mut n: u64) -> Vec<u8> {
    let mut v = vec![];
    loop {
        let b = (n & 127) as u8;
        n >>= 7;
        v.push(b | if n > 0 { 128 } else { 0 });
        if n == 0 {
            return v;
        }
    }
}
fn n(id: u64, v: u64) -> Vec<u8> {
    [vi(id << 3), vi(v)].concat()
}
fn b(id: u64, v: Vec<u8>) -> Vec<u8> {
    [vi(id << 3 | 2), vi(v.len() as u64), v].concat()
}
fn trace() -> Vec<u8> {
    let block = [n(1, 2048), n(2, 32), n(3, 8), b(5, b"R".to_vec())].concat();
    let event = [n(1, 300), n(2, 999), b(125, block)].concat();
    b(1, b(1, [n(1, 7), b(2, event)].concat()))
}
struct Fixture {
    dir: PathBuf,
    session: PathBuf,
    raw: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("perfetto-session-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(dir.join("perfetto")).unwrap();
        let session = dir.join("original.ndjson");
        let raw = dir.join("perfetto/capture.pftrace");
        std::fs::write(&session, "original interrupted recording\n").unwrap();
        std::fs::write(&raw, trace()).unwrap();
        Self { dir, session, raw }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.dir).unwrap();
    }
}

#[test]
fn raw_export_is_byte_exact_and_cannot_overwrite_original_or_existing_file() {
    let f = Fixture::new();
    let out = f.dir.join("export.pftrace");
    export_raw_trace(&f.session, &out).unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), trace());
    for dest in [&f.raw, &f.session, &out] {
        assert!(export_raw_trace(&f.session, dest).is_err());
    }
    assert_eq!(std::fs::read(&f.raw).unwrap(), trace());
    assert_eq!(
        std::fs::read_to_string(&f.session).unwrap(),
        "original interrupted recording\n"
    );
}

#[test]
fn recovery_creates_new_reopenable_sessions_and_keeps_all_unresolved_volume() {
    let f = Fixture::new();
    let first = reanalyze_saved_trace(&f.session).unwrap();
    let second = reanalyze_saved_trace(&f.session).unwrap();
    assert_ne!(first, second);
    assert_ne!(first, f.session);
    for path in [&first, &second] {
        let loaded = session::load_analysis(path).unwrap();
        let summary = loaded.engine.summary();
        assert_eq!(summary.completed_ios, 1);
        assert_eq!(summary.read_bytes, 4096);
        assert_eq!(summary.unmeasured_latency_ios, 1);
        assert_eq!(summary.p99_latency_ns, None);
        assert_eq!(summary.max_queue_depth, None);
        assert_eq!(loaded.integrity_ok, Some(true));
        assert_eq!(loaded.graceful, Some(false));
        assert!(!loaded.capabilities.unwrap().exact_file_attribution);
        assert!(loaded.loss_status.starts_with("Reanalyzed saved raw trace"));
        let WireRecord::SourceInfo { metadata, .. } = &loaded.source_info[0] else {
            panic!()
        };
        assert_eq!(metadata["recovery"]["original_preserved"], true);
        assert_eq!(raw_trace_path(path), Some(f.raw.clone()));
    }
    assert_eq!(std::fs::read(&f.raw).unwrap(), trace());
    assert_eq!(
        std::fs::read_to_string(&f.session).unwrap(),
        "original interrupted recording\n"
    );
}

#[test]
fn truncated_raw_recovery_retains_complete_prefix_and_reports_loss_of_tail() {
    let f = Fixture::new();
    let mut raw = trace();
    raw.extend([0x0a, 0x80]);
    std::fs::write(&f.raw, &raw).unwrap();
    let output = reanalyze_saved_trace(&f.session).unwrap();
    let loaded = session::load_analysis(&output).unwrap();
    assert_eq!(loaded.engine.summary().completed_ios, 1);
    assert_eq!(loaded.graceful, Some(false));
    let WireRecord::SourceInfo { metadata, .. } = &loaded.source_info[0] else {
        panic!()
    };
    assert_eq!(metadata["quality"]["truncated"], true);
    assert_eq!(std::fs::read(&f.raw).unwrap(), raw);
}

#[test]
fn shared_projection_emits_capabilities_and_stops_at_sink_failure_without_success_footer() {
    let trace = trace();
    let decoded = perfetto::decode(&trace[..]);
    let mut kinds = vec![];
    let result = project_records(&decoded, "perfetto/capture.pftrace", |record| {
        match record {
            WireRecord::SourceInfo { .. } => kinds.push("source"),
            WireRecord::Capabilities { capabilities, .. } => {
                assert!(capabilities.block_complete);
                assert!(!capabilities.block_issue);
                kinds.push("capabilities");
            }
            WireRecord::Event {
                event: StorageEvent::ObservedBlockCompletion(_),
                ..
            } => return Err(anyhow::anyhow!("disk full")),
            WireRecord::Footer { .. } => panic!("failed sink received success footer"),
            _ => panic!(),
        };
        Ok(())
    });
    assert!(result.unwrap_err().to_string().contains("disk full"));
    assert_eq!(kinds, ["source", "capabilities"]);
}

#[test]
fn reopening_service_loss_shows_it_even_when_kernel_loss_is_zero() {
    let f = Fixture::new();
    let mut decoded = perfetto::decode(&trace()[..]);
    decoded.quality.ftrace_start_seen = true;
    decoded.quality.ftrace_end_seen = true;
    decoded.quality.kernel_start.insert(0, [Some(0); 3]);
    decoded.quality.kernel_end.insert(0, [Some(0); 3]);
    decoded.quality.service_stats_seen = true;
    decoded
        .quality
        .service_loss_counters
        .insert("buffer_0_bytes_overwritten".into(), 32768);
    decoded
        .quality
        .service_loss_counters
        .insert("buffer_0_chunks_overwritten".into(), 1);
    let path = f.dir.join("service-loss.ndjson");
    let mut writer = std::io::BufWriter::new(std::fs::File::create(&path).unwrap());
    project_records(&decoded, "perfetto/capture.pftrace", |record| {
        android_ebpf_protocol::write_record(&mut writer, &record)?;
        Ok(())
    })
    .unwrap();
    drop(writer);
    let loaded = session::load_analysis(&path).unwrap();
    assert!(loaded.loss_status.contains("kernel loss 0"));
    assert!(
        loaded.loss_status.contains("Service loss detected"),
        "{}",
        loaded.loss_status
    );
    assert!(loaded.loss_status.contains("32768 bytes overwritten"));
    assert!(loaded.loss_status.contains("1 chunks overwritten"));
    assert_eq!(loaded.engine.summary().completed_ios, 1);
    assert_eq!(loaded.engine.summary().read_bytes, 4096);
    assert_eq!(loaded.engine.summary().p99_latency_ns, None);
}

#[test]
fn source_quality_preserves_unknown_counters_and_distinct_failure_reasons() {
    let mut quality = perfetto::TraceQuality::default();
    let mut metadata = serde_json::json!({"stage":"complete", "quality":quality});
    let unknown = source_status("perfetto", "Perfetto capture", &metadata);
    assert!(unknown.contains("Service loss counters unavailable"));
    assert!(!unknown.contains("Service loss detected"));
    quality.service_stats_seen = true;
    quality.lost_bundles = 3;
    quality.parse_errors = 2;
    quality.truncated = true;
    quality.projection_limited = true;
    quality.final_flush_outcome = Some(2);
    metadata["quality"] = serde_json::to_value(quality).unwrap();
    let status = source_status("perfetto", "Perfetto capture", &metadata);
    for reason in [
        "Lost ftrace bundles: 3",
        "Trace parse errors: 2",
        "Raw trace truncated",
        "Analysis projection limit reached",
        "Final trace flush failed",
    ] {
        assert!(status.contains(reason), "{status}");
    }
    assert_eq!(
        source_status("other", "Original source", &metadata),
        "Original source"
    );
    metadata["stage"] = "recording".into();
    assert_eq!(
        source_status("perfetto", "Still recording", &metadata),
        "Still recording"
    );
}

#[test]
fn metadata_cannot_redirect_raw_export_to_an_unrelated_file() {
    let f = Fixture::new();
    std::fs::remove_file(&f.raw).unwrap();
    std::fs::write(
        &f.session,
        "{\"record\":\"source_info\",\"metadata\":{\"raw_trace\":\"../secret\"}}\n",
    )
    .unwrap();
    assert_eq!(raw_trace_path(&f.session), None);
    assert!(export_raw_trace(&f.session, &f.dir.join("output.pftrace")).is_err());
}

#[test]
#[ignore = "requires ANDROID_EBPF_FAKE_PERFETTO_ADB host fixture executable"]
fn root_start_failure_automatically_uses_perfetto_without_mixing_later_failures() {
    use android_ebpf_studio::{
        adb::AdbClient,
        capture::{self, HostMessage},
    };
    let executable = std::env::var_os("ANDROID_EBPF_FAKE_PERFETTO_ADB").unwrap();
    for (behavior, available, fail_start, reboot, expect_perfetto, expect_counters) in [
        ("fail", true, false, false, true, false),
        ("empty-success", true, false, false, true, false),
        ("fail", false, false, false, false, true),
        ("fail", true, true, false, false, true),
        ("ready-then-fail", true, false, false, false, false),
        ("data-then-fail", true, false, false, false, false),
        ("stop-then-fail", true, false, false, false, false),
        ("cancel-recheck", true, false, false, false, false),
        ("fail", true, false, true, false, false),
    ] {
        let f = Fixture::new();
        std::fs::remove_file(&f.raw).unwrap(); // This matrix starts a new capture.
        let adb = f.dir.join("fake-adb.exe");
        std::fs::copy(&executable, &adb).unwrap();
        std::fs::write(f.dir.join("source.pftrace"), trace()).unwrap();
        std::fs::write(f.dir.join("fixture.json"), serde_json::to_vec(&serde_json::json!({
            "capture_test":true,"serial":"root-fixture","boot":"boot-old","ticks":999,
            "agent_behavior":behavior,"perfetto":available,"fail_start":fail_start,"reboot_after_failure":reboot
        })).unwrap()).unwrap();
        let (tx, rx) = crossbeam_channel::bounded(1000);
        let handle = capture::start_adb(
            AdbClient::new(&adb),
            "root-fixture".into(),
            adb.clone(),
            adb,
            "fallback-test".into(),
            f.dir.join("agent.jsonl"),
            "info".into(),
            tx,
        );
        let started = std::time::Instant::now();
        let mut perfetto = false;
        let mut counters = false;
        let mut observations = 0;
        let mut root_events = 0;
        let mut recorded_failure = false;
        let mut fallback_report = None;
        let mut diagnostics = Vec::new();
        let result = loop {
            assert!(started.elapsed() < std::time::Duration::from_secs(30));
            match rx.recv_timeout(std::time::Duration::from_secs(15)).unwrap() {
                HostMessage::Preflight(Ok(report)) => {
                    fallback_report = Some(report);
                }
                HostMessage::Record(WireRecord::SourceInfo {
                    source, metadata, ..
                }) if source == "perfetto" && metadata["stage"] == "recording" => {
                    perfetto = true;
                    handle.stop();
                }
                HostMessage::Status(status) if status.starts_with("Recording device counters") => {
                    counters = true
                }
                HostMessage::Record(WireRecord::SourceInfo {
                    source, metadata, ..
                }) if source == "ebpf" => {
                    recorded_failure =
                        metadata["stage"] == "fallback" && metadata["error"].as_str().is_some();
                }
                HostMessage::Record(WireRecord::DiskStats { .. }) => {
                    handle.stop();
                }
                HostMessage::Record(WireRecord::Event {
                    event: StorageEvent::ObservedBlockCompletion(_),
                    ..
                }) => observations += 1,
                HostMessage::Record(WireRecord::Event { .. }) => root_events += 1,
                HostMessage::Record(WireRecord::Health { .. }) if behavior == "stop-then-fail" => {
                    handle.stop();
                    handle.stop();
                }
                HostMessage::Ended(result) => break result,
                HostMessage::Diagnostic(record) => {
                    if behavior == "cancel-recheck" && record.code == "EBPF_UNAVAILABLE" {
                        handle.stop();
                    }
                    diagnostics.push(format!("{record:?}"));
                }
                _ => {}
            }
        };
        assert_eq!(
            perfetto, expect_perfetto,
            "{behavior}, service={available}, start failure={fail_start}, reboot={reboot}: {result:?} {diagnostics:?}"
        );
        assert_eq!(counters, expect_counters);
        assert_eq!(observations, usize::from(expect_perfetto));
        assert_eq!(root_events, usize::from(behavior == "data-then-fail"));
        assert_eq!(
            recorded_failure,
            expect_perfetto || expect_counters || behavior == "cancel-recheck"
        );
        assert_eq!(
            result.is_ok(),
            expect_perfetto || expect_counters || behavior == "cancel-recheck"
        );
        let commands = std::fs::read_to_string(f.dir.join("commands.jsonl")).unwrap();
        assert_eq!(
            commands.contains("--background-wait"),
            expect_perfetto || fail_start
        );
        if expect_perfetto {
            let report = fallback_report.unwrap();
            assert!(!report.full_ebpf_ready());
            assert!(report.perfetto);
            assert!(f.dir.join("perfetto/capture.pftrace").is_file());
            let profile: serde_json::Value =
                serde_json::from_slice(&std::fs::read(f.dir.join("device-profile.json")).unwrap())
                    .unwrap();
            assert!(profile["ebpf_start_error"].as_str().is_some());
        }
    }
}

#[test]
#[ignore = "requires ANDROID_EBPF_FAKE_PERFETTO_ADB host fixture executable"]
fn phone_recovery_checks_boot_and_pid_lifetime_and_preserves_failure_data() {
    use android_ebpf_studio::{adb::AdbClient, perfetto_capture::PerfettoOwner};
    let executable = std::env::var_os("ANDROID_EBPF_FAKE_PERFETTO_ADB").unwrap();
    for (boot, ticks, fail_pull, expect_signal) in [
        ("boot-old", 999, false, true),
        ("boot-new", 999, false, false),
        ("boot-old", 1000, false, false),
        ("boot-old", 999, true, true),
    ] {
        let f = Fixture::new();
        let adb = f.dir.join("fake-adb.exe");
        std::fs::copy(&executable, &adb).unwrap();
        std::fs::write(f.dir.join("source.pftrace"), trace()).unwrap();
        let token = uuid::Uuid::new_v4().to_string();
        let owner = PerfettoOwner {
            serial: "fixture-phone".into(),
            boot_id: "boot-old".into(),
            token: token.clone(),
            remote_config: format!("/data/misc/perfetto-configs/aebpf-{token}.pbtxt"),
            remote_trace: format!("/data/misc/perfetto-traces/aebpf-{token}.pftrace"),
            pid: Some(42),
            process_start_ticks: Some(999),
            duration_ms: 30000,
            local_trace: f.raw.clone(),
        };
        std::fs::write(f.dir.join("fixture.json"),serde_json::to_vec(&serde_json::json!({"serial":owner.serial,"boot":boot,"ticks":ticks,"remote_config":owner.remote_config,"remote_trace":owner.remote_trace,"fail_pull":fail_pull})).unwrap()).unwrap();
        std::fs::write(
            f.dir.join("perfetto/perfetto-owner.json"),
            serde_json::to_vec(&owner).unwrap(),
        )
        .unwrap();
        if !fail_pull {
            std::fs::remove_file(&f.raw).unwrap();
        }
        let result = recover_from_phone(AdbClient::new(&adb), &f.session);
        assert_eq!(result.is_err(), fail_pull, "{result:?}");
        if let Ok(output) = result {
            assert_eq!(
                session::load_analysis(&output)
                    .unwrap()
                    .engine
                    .summary()
                    .read_bytes,
                4096
            );
        }
        let log = std::fs::read_to_string(f.dir.join("commands.jsonl")).unwrap();
        assert_eq!(log.contains("kill"), expect_signal);
        for line in log.lines() {
            let args: Vec<String> = serde_json::from_str(line).unwrap();
            assert_eq!(&args[..2], ["-s", "fixture-phone"]);
        }
        assert_eq!(std::fs::read(&f.raw).unwrap(), trace());
        assert_eq!(
            std::fs::read_to_string(&f.session).unwrap(),
            "original interrupted recording\n"
        );
    }
}
