use android_ebpf_studio::graph_summary::HistogramBin;

#[test]
fn address_histogram_bars_stay_inside_their_bins() {
    // V2602DA raw address histogram: 1.306624 MB bin at a 38,563 MB offset.
    for (lower, upper) in [
        (38563.192832, 38564.499456),
        (0.0, 0.00000001),
        (-38564.499456, -38563.192832),
    ] {
        let bin = HistogramBin {
            lower,
            upper,
            count: 73,
        };
        let width = bin.plot_width();
        assert!(
            width > 0.0 && width <= upper - lower,
            "bar {width} exceeds bin {}",
            upper - lower
        );
    }
}

#[test]
fn constant_histogram_has_a_visible_finite_bar() {
    for value in [0.0, 1.0, 38563.192832] {
        let bin = HistogramBin {
            lower: value,
            upper: value,
            count: 12,
        };
        assert!(bin.plot_width().is_finite() && bin.plot_width() > 0.0);
    }
}
