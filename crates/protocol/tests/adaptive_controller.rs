use android_ebpf_protocol::{AdaptiveController, CaptureState, TriggerPolicy};

#[test]
fn controller_requires_consecutive_windows_and_cools_down() {
    let mut controller = AdaptiveController::new(TriggerPolicy {
        rule: "p99_total".into(),
        threshold: 5_000_000,
        consecutive_windows: 3,
        deep_duration_ns: 10_000,
        cooldown_ns: 5_000,
        arming_timeout_ns: 4_000,
    })
    .unwrap();

    let armed = controller.observe(1_000, 6_000_000, 2).unwrap();
    assert_eq!(
        (armed.from, armed.to),
        (CaptureState::Basic, CaptureState::Armed)
    );
    assert!(controller.observe(2_000, 6_000_000, 2).is_none());
    let deep = controller.observe(3_000, 7_000_000, 2).unwrap();
    assert_eq!(
        (deep.from, deep.to),
        (CaptureState::Armed, CaptureState::Deep)
    );

    let cooldown = controller.tick(13_000, 2).unwrap();
    assert_eq!(
        (cooldown.from, cooldown.to),
        (CaptureState::Deep, CaptureState::Cooldown)
    );
    assert!(controller.tick(17_999, 2).is_none());
    let basic = controller.tick(18_000, 2).unwrap();
    assert_eq!(
        (basic.from, basic.to),
        (CaptureState::Cooldown, CaptureState::Basic)
    );
}

#[test]
fn controller_disarms_when_the_signal_recovers() {
    let mut controller = AdaptiveController::new(TriggerPolicy {
        rule: "queue".into(),
        threshold: 10,
        consecutive_windows: 2,
        deep_duration_ns: 100,
        cooldown_ns: 100,
        arming_timeout_ns: 100,
    })
    .unwrap();
    controller.observe(1, 11, 1).unwrap();
    let recovered = controller.observe(2, 9, 1).unwrap();
    assert_eq!(recovered.to, CaptureState::Basic);
    assert_eq!(recovered.reason, "signal_recovered");
}
