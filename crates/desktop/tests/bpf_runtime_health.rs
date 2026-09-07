use android_ebpf_studio::session::load_analysis;
use std::fs;
#[test]
fn replay_does_not_hide_bpf_recursion_misses_behind_zero_ring_loss() {
    let path = std::env::temp_dir().join(format!("bpf-recursion-{}.ndjson", std::process::id()));
    fs::write(&path, r#"{"record":"health","schema_version":6,"emitted_events":0,"kernel_drops":0,"userspace_drops":0,"probe_health":{"runtime.block_rq_complete":{"emitted":0,"reserve_failures":0,"paired":0,"unpaired":0,"recursion_misses":9}},"correlation_ambiguous":0,"correlation_expired":0,"key_reused":0}
"#).unwrap();
    let loaded = load_analysis(&path).unwrap();
    fs::remove_file(path).unwrap();
    assert!(
        loaded.loss_status.contains("BPF recursion misses: 9"),
        "{}",
        loaded.loss_status
    );
}

#[test]
fn legacy_health_keeps_runtime_loss_unmeasured() {
    let path = std::env::temp_dir().join(format!("bpf-legacy-{}.ndjson", std::process::id()));
    fs::write(&path, r#"{"record":"health","schema_version":6,"emitted_events":0,"kernel_drops":0,"userspace_drops":0,"probe_health":{},"correlation_ambiguous":0,"correlation_expired":0,"key_reused":0}
"#).unwrap();
    let loaded = load_analysis(&path).unwrap();
    fs::remove_file(path).unwrap();
    assert!(
        loaded
            .loss_status
            .contains("BPF recursion misses: not reported"),
        "{}",
        loaded.loss_status
    );
}
#[test]
fn runtime_counter_roundtrip_preserves_missing_and_large_values() {
    let absent: android_ebpf_protocol::ProbeHealth =
        serde_json::from_str(r#"{"emitted":0,"reserve_failures":0,"paired":0,"unpaired":0}"#)
            .unwrap();
    assert_eq!(absent.recursion_misses, None);
    let mut present = absent;
    present.recursion_misses = Some(u64::MAX);
    let decoded: android_ebpf_protocol::ProbeHealth =
        serde_json::from_str(&serde_json::to_string(&present).unwrap()).unwrap();
    assert_eq!(decoded.recursion_misses, Some(u64::MAX));
}
