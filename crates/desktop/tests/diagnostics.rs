use std::fs;

use android_ebpf_protocol::DiagnosticLevel;
use android_ebpf_studio::diagnostics::{RotatingJsonl, export_bundle, host_record, parse_agent_diagnostic};

#[test]
fn diagnostic_log_rotates_and_redacts_device_paths() {
    let root = std::env::temp_dir().join(format!("studio-diag-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let path = root.join("host.jsonl");
    let mut writer = RotatingJsonl::with_limits(&path, 220, 2).unwrap();
    for _ in 0..5 {
        writer
            .append(&host_record(
                "session",
                DiagnosticLevel::Info,
                "test",
                "TEST",
                "success",
                Some("file=/data/local/tmp/private.bin".into()),
            ))
            .unwrap();
    }
    drop(writer);
    let current = fs::read_to_string(&path).unwrap();
    assert!(!current.contains("private.bin"));
    assert!(root.join("host.1.jsonl").is_file());
    fs::remove_dir_all(root).ok();
}

#[test]
fn invalid_agent_line_is_bounded_and_redacted_before_ui_delivery() {
    let record = parse_agent_diagnostic("bad /data/local/tmp/secret.bin", "session");
    assert_eq!(record.code, "AGENT_DIAGNOSTIC_INVALID");
    assert!(!record.detail.unwrap_or_default().contains("secret.bin"));
}

#[test]
fn diagnostic_bundle_excludes_raw_session_by_default() {
    let root = std::env::temp_dir().join(format!("studio-bundle-{}", std::process::id()));
    let logs = root.join("logs");
    let output = root.join("bundle");
    fs::create_dir_all(&logs).unwrap();
    fs::write(logs.join("host.jsonl"), "{}\n").unwrap();
    let session = root.join("session.ndjson");
    fs::write(&session, "sensitive path").unwrap();

    let metadata = serde_json::json!({"log_level": "info", "last_sequence": 3});
    export_bundle(&output, &logs, Some(&session), false, Some(&metadata)).unwrap();
    assert!(output.join("manifest.json").is_file());
    assert!(output.join("capture-profile.json").is_file());
    assert!(output.join("host.jsonl").is_file());
    assert!(!output.join("session.ndjson").exists());
    fs::remove_dir_all(root).ok();
}
