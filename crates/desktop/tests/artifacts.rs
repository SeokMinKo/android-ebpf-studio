use android_ebpf_studio::artifacts::{CapturePathError, CapturePaths};
use std::fs;

#[test]
fn release_bundle_artifacts_and_session_path_are_automatic() {
    let root =
        std::env::temp_dir().join(format!("android-ebpf-studio-paths-{}", std::process::id()));
    let bundle = root.join("bundle");
    let sessions = root.join("sessions");
    fs::create_dir_all(&bundle).unwrap();
    fs::write(bundle.join("android-ebpf-agent"), b"agent").unwrap();
    fs::write(bundle.join("android-storage-ebpf.o"), b"bpf").unwrap();
    let paths =
        CapturePaths::discover_from(&bundle.join("android-ebpf-studio.exe"), &root, &sessions)
            .unwrap();
    assert_eq!(paths.agent, bundle.join("android-ebpf-agent"));
    assert_eq!(paths.bpf_object, bundle.join("android-storage-ebpf.o"));
    assert_eq!(paths.session.parent(), Some(sessions.as_path()));
    assert_eq!(
        paths.session.extension().and_then(|value| value.to_str()),
        Some("ndjson")
    );
    assert!(paths.log_directory.is_dir());
    assert_eq!(paths.host_log.file_name().unwrap(), "host.jsonl");
    assert_eq!(paths.agent_log.file_name().unwrap(), "agent.jsonl");
    assert!(!paths.session_id.is_empty());
    fs::remove_dir_all(root).ok();
}

#[test]
fn missing_agent_is_actionable() {
    let root = std::env::temp_dir().join(format!(
        "android-ebpf-studio-missing-{}",
        std::process::id()
    ));
    fs::create_dir_all(&root).unwrap();
    let result =
        CapturePaths::discover_from(&root.join("studio.exe"), &root, &root.join("sessions"));
    assert!(matches!(result, Err(CapturePathError::AgentNotFound)));
    fs::remove_dir_all(root).ok();
}
