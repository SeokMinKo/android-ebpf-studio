use android_ebpf_protocol::WireRecord;
use android_ebpf_studio::{
    adb::{AdbClient, RootMethod},
    capture::{self, HostMessage},
};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

fn fixture() -> PathBuf {
    PathBuf::from(
        std::env::var_os("ANDROID_EBPF_FAKE_ADB")
            .expect("build examples/fake_adb then set ANDROID_EBPF_FAKE_ADB"),
    )
}

#[test]
#[ignore = "requires host fixture executable ANDROID_EBPF_FAKE_ADB"]
fn phones_with_different_root_methods_get_fresh_scoped_profiles() {
    let client = AdbClient::new(fixture());
    let first = client.preflight("root-phone").unwrap();
    let second = client.preflight("su-phone").unwrap();
    assert_eq!(first.root_method, RootMethod::Shell);
    assert_eq!(second.root_method, RootMethod::SuCommand);
    assert_ne!(first.boot_id, second.boot_id);
    assert_ne!(first.build_fingerprint, second.build_fingerprint);
    assert_eq!(second.serial, "su-phone");
    assert!(second.full_ebpf_ready());
    assert!(client.preflight("root-phone").unwrap().full_ebpf_ready());
    assert!(
        first.perfetto,
        "Root preflight must also detect available fallback tracing"
    );
}

#[test]
#[ignore = "requires host fixture executable ANDROID_EBPF_FAKE_ADB"]
fn stop_drains_tail_health_and_footer_before_ended() {
    let fake = fixture();
    let dir = std::env::temp_dir().join(format!("studio-transport-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    let (tx, rx) = crossbeam_channel::bounded(1000);
    let handle = capture::start_adb(
        AdbClient::new(&fake),
        "root-phone".into(),
        fake.clone(),
        fake,
        "fixture-session".into(),
        dir.join("agent.jsonl"),
        "info".into(),
        tx,
    );
    let started = Instant::now();
    let mut stopped = false;
    let mut tail = false;
    let mut footer = false;
    loop {
        assert!(started.elapsed() < Duration::from_secs(15));
        match rx.recv_timeout(Duration::from_secs(10)).unwrap() {
            HostMessage::Record(WireRecord::Health {
                emitted_events: 0, ..
            }) => {
                handle.stop();
                handle.stop();
                stopped = true;
            }
            HostMessage::Record(WireRecord::Health {
                emitted_events: 123,
                kernel_drops: Some(7),
                ..
            }) => tail = true,
            HostMessage::Record(WireRecord::Footer {
                graceful: Some(true),
                ..
            }) => footer = true,
            HostMessage::Ended(result) => {
                assert!(result.is_ok(), "{result:?}");
                break;
            }
            _ => {}
        }
    }
    assert!(stopped && tail && footer);
    assert!(dir.join("device-profile.json").is_file());
}

#[test]
#[ignore = "requires host fixture executable ANDROID_EBPF_FAKE_ADB"]
fn unsupported_abi_records_counters_without_inventing_individual_io() {
    let fake = fixture();
    let dir = std::env::temp_dir().join(format!("studio-counter-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    let (tx, rx) = crossbeam_channel::bounded(1000);
    let handle = capture::start_adb(
        AdbClient::new(&fake),
        "counter-phone".into(),
        fake.clone(),
        fake,
        "counter-test".into(),
        dir.join("agent.jsonl"),
        "info".into(),
        tx,
    );
    let mut counters = 0;
    loop {
        match rx.recv_timeout(Duration::from_secs(15)).unwrap() {
            HostMessage::Record(WireRecord::DiskStats { raw, boot_id, .. }) => {
                assert!(raw.contains("sda1"));
                assert_eq!(boot_id, "boot-counter-phone");
                counters += 1;
                handle.stop();
            }
            HostMessage::Record(WireRecord::Event { .. }) => {
                panic!("counter fallback invented an event")
            }
            HostMessage::Ended(result) => {
                assert!(result.is_ok(), "{result:?}");
                break;
            }
            _ => {}
        }
    }
    assert!(counters > 0);
}

#[test]
#[ignore = "requires host fixture executable ANDROID_EBPF_FAKE_ADB"]
fn disconnect_preserves_delivered_records_and_reports_failure() {
    let fake = fixture();
    let dir = std::env::temp_dir().join(format!("studio-disconnect-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    let (tx, rx) = crossbeam_channel::bounded(1000);
    let _handle = capture::start_adb(
        AdbClient::new(&fake),
        "disconnect-phone".into(),
        fake.clone(),
        fake,
        "disconnect-test".into(),
        dir.join("agent.jsonl"),
        "info".into(),
        tx,
    );
    let mut health = false;
    loop {
        match rx.recv_timeout(Duration::from_secs(15)).unwrap() {
            HostMessage::Record(WireRecord::Health { .. }) => health = true,
            HostMessage::Ended(result) => {
                assert!(result.is_err());
                break;
            }
            _ => {}
        }
    }
    assert!(health);
}
