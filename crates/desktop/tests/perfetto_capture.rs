use android_ebpf_studio::{
    adb::AdbClient,
    perfetto_capture::{PerfettoCapture, PerfettoOwner, process_identity},
};
#[test]
fn process_identity_handles_parentheses_and_never_uses_pid_as_lifetime() {
    let mut fields = vec!["S".to_owned(); 20];
    fields[19] = "123456".into();
    assert_eq!(
        process_identity(&format!("42 (name (with) spaces) {}", fields.join(" "))),
        Some(('S', 123456))
    );
    assert_eq!(process_identity("42 (perfetto) S 1 2"), None);
}
#[test]
fn recovery_rejects_foreign_remote_paths_and_host_destination() {
    let dir = std::env::temp_dir().join(format!("perfetto-recovery-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    let token = uuid::Uuid::new_v4().to_string();
    let mut owner = PerfettoOwner {
        serial: "test".into(),
        boot_id: "boot".into(),
        token: token.clone(),
        remote_config: format!("/data/misc/perfetto-configs/aebpf-{token}.pbtxt"),
        remote_trace: "/data/local/tmp/unrelated".into(),
        pid: Some(42),
        process_start_ticks: Some(999),
        duration_ms: 30000,
        local_trace: dir.join("capture.pftrace"),
    };
    let manifest = dir.join("perfetto-owner.json");
    std::fs::write(&manifest, serde_json::to_vec(&owner).unwrap()).unwrap();
    assert!(PerfettoCapture::recover(AdbClient::default(), &manifest).is_err());
    owner.remote_trace = format!("/data/misc/perfetto-traces/aebpf-{token}.pftrace");
    owner.local_trace = dir.join("../unrelated.pftrace");
    std::fs::write(&manifest, serde_json::to_vec(&owner).unwrap()).unwrap();
    assert!(PerfettoCapture::recover(AdbClient::default(), &manifest).is_err());
    std::fs::remove_file(manifest).unwrap();
    std::fs::remove_dir(dir).unwrap();
}

#[test]
fn transport_failure_preserves_existing_trace_and_recovery_manifest() {
    let dir = std::env::temp_dir().join(format!("perfetto-recovery-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    let token = uuid::Uuid::new_v4().to_string();
    let owner = PerfettoOwner {
        serial: "test".into(),
        boot_id: "boot".into(),
        token: token.clone(),
        remote_config: format!("/data/misc/perfetto-configs/aebpf-{token}.pbtxt"),
        remote_trace: format!("/data/misc/perfetto-traces/aebpf-{token}.pftrace"),
        pid: Some(42),
        process_start_ticks: Some(999),
        duration_ms: 30000,
        local_trace: dir.join("capture.pftrace"),
    };
    let manifest = dir.join("perfetto-owner.json");
    std::fs::write(&manifest, serde_json::to_vec(&owner).unwrap()).unwrap();
    std::fs::write(&owner.local_trace, b"original raw bytes").unwrap();
    let capture =
        PerfettoCapture::recover(AdbClient::new(dir.join("missing-adb.exe")), &manifest).unwrap();
    assert!(capture.stop_and_pull().is_err());
    assert!(capture.pull().is_err());
    assert_eq!(
        std::fs::read(&owner.local_trace).unwrap(),
        b"original raw bytes"
    );
    assert!(manifest.exists());
    std::fs::remove_file(&owner.local_trace).unwrap();
    std::fs::remove_file(manifest).unwrap();
    std::fs::remove_dir(dir).unwrap();
}
