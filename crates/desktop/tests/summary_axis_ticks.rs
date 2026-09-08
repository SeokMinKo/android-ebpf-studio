use android_ebpf_studio::graph_summary::summary_tick;

#[test]
fn neighboring_address_ticks_are_distinguishable_and_accurate() {
    for offset in [38560.0, -38580.0] {
        let labels: Vec<_> = (0..4)
            .map(|i| summary_tick(offset + i as f64 * 5.0, 24.0))
            .collect();
        assert!(labels.windows(2).all(|w| w[0] != w[1]), "{labels:?}");
        for (i, label) in labels.iter().enumerate() {
            let value = label.trim_end_matches('k').parse::<f64>().unwrap() * 1000.0;
            assert!((value - (offset + i as f64 * 5.0)).abs() < 0.5);
        }
    }
}

#[test]
fn tiny_fractional_ticks_do_not_all_round_to_zero() {
    assert_ne!(
        summary_tick(0.000001, 0.000004),
        summary_tick(0.000002, 0.000004)
    );
}
