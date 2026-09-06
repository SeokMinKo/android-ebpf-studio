use android_ebpf_protocol::{BlockComplete, BlockIssue, IoOperation, RequestCorrelator};

#[test]
fn old_completions_stay_unmeasured_and_new_cpu_zero_round_trips() {
    let old = r#"{"ts_ns":20,"request_id":1,"device_major":8,"device_minor":0,"status":0}"#;
    let mut completion: BlockComplete = serde_json::from_str(old).unwrap();
    assert_eq!(completion.cpu, None);
    assert!(
        !serde_json::to_value(&completion)
            .unwrap()
            .as_object()
            .unwrap()
            .contains_key("cpu")
    );
    completion.cpu = Some(0);
    let decoded: BlockComplete =
        serde_json::from_str(&serde_json::to_string(&completion).unwrap()).unwrap();
    assert_eq!(decoded.cpu, Some(0));
}

#[test]
fn request_correlation_preserves_different_issue_and_completion_cpu() {
    let mut correlator = RequestCorrelator::new(1_000_000);
    correlator.on_issue(BlockIssue {
        ts_ns: 10,
        request_id: 1,
        device_major: 8,
        device_minor: 0,
        sector: 0,
        sectors: 8,
        bytes: 4096,
        operation: IoOperation::Read,
        pid: 1,
        tid: 1,
        cpu: 2,
        comm: "worker".into(),
    });
    let io = correlator
        .on_complete(BlockComplete {
            ts_ns: 20,
            request_id: 1,
            device_major: 8,
            device_minor: 0,
            status: 0,
            cpu: Some(7),
        })
        .unwrap();
    assert_eq!(io.issuer_cpu(), Some(2));
    assert_eq!(io.completion.cpu, Some(7));
}
