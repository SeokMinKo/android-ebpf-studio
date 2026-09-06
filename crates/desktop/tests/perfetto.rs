use android_ebpf_studio::perfetto::{analyze, decode};

fn vi(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let b = (value & 127) as u8;
        value >>= 7;
        out.push(b | if value > 0 { 128 } else { 0 });
        if value == 0 {
            return out;
        }
    }
}
fn n(id: u64, value: u64) -> Vec<u8> {
    [vi(id << 3), vi(value)].concat()
}
fn b(id: u64, value: impl AsRef<[u8]>) -> Vec<u8> {
    let value = value.as_ref();
    [vi(id << 3 | 2), vi(value.len() as u64), value.to_vec()].concat()
}
fn event(kind: u64, ts: u64, tid: u64, sector: u64, sectors: u64) -> Vec<u8> {
    let mut block = [n(1, 2048), n(2, sector), n(3, sectors), b(5, "R")].concat();
    if kind == 45 || kind == 126 {
        block.extend(n(4, sectors * 512));
        block.extend(b(6, "issuer-thread"));
    }
    [n(1, ts), n(2, tid), b(kind, block)].concat()
}
fn packet(cpu: u64, events: Vec<Vec<u8>>, lost: bool) -> Vec<u8> {
    let mut bundle = n(1, cpu);
    for e in events {
        bundle.extend(b(2, e));
    }
    if lost {
        bundle.extend(n(3, 1));
    }
    b(1, b(1, bundle))
}

#[test]
fn sorts_cpu_packets_and_matches_only_probably_without_using_completion_tid_as_issuer() {
    let trace = [
        packet(1, vec![event(125, 2000, 999, 32, 8)], false),
        packet(0, vec![event(45, 1000, 42, 32, 8)], false),
    ]
    .concat();
    let d = decode(&trace[..]);
    let a = analyze(&d);
    let io = &a.completions[0];
    assert_eq!(d.events.len(), 2);
    assert_eq!(io.device_latency_ns, Some(1000));
    assert_eq!(io.queue_latency_ns, None);
    assert_eq!(io.issuer_tid, Some(42));
    assert_eq!(io.timing_confidence, "Probable");
    assert_eq!(io.bytes, 4096);
    assert_eq!(d.quality.kernel_lost_events(), None);
}
#[test]
fn duplicate_ranges_preserve_both_completions_and_candidates_without_false_latency() {
    let trace = packet(
        0,
        vec![
            event(45, 10, 42, 32, 8),
            event(45, 11, 43, 32, 8),
            event(125, 20, 999, 32, 8),
            event(125, 21, 999, 32, 8),
        ],
        false,
    );
    let d = decode(&trace[..]);
    let a = analyze(&d);
    assert_eq!(a.completions.len(), 2);
    assert_eq!(a.completions.iter().map(|v| v.bytes).sum::<u64>(), 8192);
    for io in &a.completions {
        assert_eq!(io.issue_candidates.len(), 2);
        assert_eq!(io.device_latency_ns, None);
        assert_eq!(io.issuer_tid, None);
    }
}
#[test]
fn partial_completion_and_requeue_do_not_create_normal_latency() {
    for events in [
        vec![
            event(45, 10, 42, 32, 16),
            event(125, 20, 999, 32, 8),
            event(125, 30, 999, 40, 8),
        ],
        vec![
            event(45, 10, 42, 32, 8),
            event(129, 15, 999, 32, 8),
            event(45, 20, 42, 32, 8),
            event(125, 30, 999, 32, 8),
        ],
    ] {
        let trace = packet(0, events, false);
        let d = decode(&trace[..]);
        let a = analyze(&d);
        assert!(!a.completions.is_empty());
        assert!(a.completions.iter().all(|v| v.device_latency_ns.is_none()));
    }
}
#[test]
fn loss_and_truncated_tail_preserve_volume_but_invalidate_timing() {
    let valid = packet(
        0,
        vec![event(45, 10, 42, 32, 8), event(125, 20, 999, 32, 8)],
        false,
    );
    let lost = packet(
        0,
        vec![event(45, 10, 42, 32, 8), event(125, 20, 999, 32, 8)],
        true,
    );
    let tail = [valid, vec![0x0a, 0x80]].concat();
    for trace in [lost, tail] {
        let d = decode(&trace[..]);
        let a = analyze(&d);
        assert_eq!(a.completions.len(), 1);
        assert_eq!(a.completions[0].bytes, 4096);
        assert_eq!(a.completions[0].device_latency_ns, None);
    }
}
#[test]
fn queue_time_requires_unique_insert_and_distinct_timestamp_order() {
    let trace = packet(
        0,
        vec![
            event(126, 1, 42, 32, 8),
            event(45, 10, 42, 32, 8),
            event(125, 20, 999, 32, 8),
        ],
        false,
    );
    let a = analyze(&decode(&trace[..]));
    assert_eq!(a.completions[0].queue_latency_ns, Some(9));
    let trace = packet(
        0,
        vec![event(45, 10, 42, 32, 8), event(125, 10, 999, 32, 8)],
        false,
    );
    assert_eq!(
        analyze(&decode(&trace[..])).completions[0].device_latency_ns,
        None
    );
}
#[test]
fn unknown_and_missing_fields_never_panic_or_invent_a_zero_timestamp() {
    let trace = packet(
        0,
        vec![b(
            45,
            [n(1, 2048), n(2, 32), n(3, 8), n(4, 4096), b(5, "R")].concat(),
        )],
        false,
    );
    let d = decode(&trace[..]);
    assert_eq!(d.events.len(), 0);
    assert!(d.quality.parse_errors > 0);
    let full = packet(
        0,
        vec![event(45, 10, 42, 32, 8), event(125, 20, 999, 32, 8)],
        false,
    );
    for length in 0..full.len() {
        let partial = decode(&full[..length]);
        assert!(partial.events.is_empty());
        if length > 0 {
            assert!(partial.quality.truncated);
        }
    }
    let mut malformed = vec![0x0a];
    malformed.extend([0xff; 10]);
    assert!(decode(&malformed[..]).quality.truncated);
}

#[test]
fn service_buffer_loss_and_unsupported_clock_prevent_false_timing() {
    let events = vec![event(45, 10, 42, 32, 8), event(125, 20, 999, 32, 8)];
    let trace = [
        packet(0, events.clone(), false),
        b(1, b(35, b(1, n(13, 42)))),
    ]
    .concat();
    let d = decode(&trace[..]);
    assert_eq!(
        d.quality.service_loss_counters["buffer_0_bytes_overwritten"],
        42
    );
    assert_eq!(analyze(&d).completions[0].device_latency_ns, None);
    let mut bundle = [n(1, 0), n(5, 3)].concat();
    for e in events {
        bundle.extend(b(2, e));
    }
    let trace = b(1, b(1, bundle));
    let d = decode(&trace[..]);
    assert!(d.quality.unsupported_clocks.contains(&3));
    assert_eq!(analyze(&d).completions[0].device_latency_ns, None);
}

#[test]
fn kernel_counter_resets_and_missing_cpu_samples_are_unknown() {
    use android_ebpf_studio::perfetto::TraceQuality;
    let mut q = TraceQuality {
        ftrace_start_seen: true,
        ftrace_end_seen: true,
        ..Default::default()
    };
    q.kernel_start.insert(0, [Some(10), Some(0), Some(0)]);
    q.kernel_end.insert(0, [Some(9), Some(0), Some(0)]);
    assert_eq!(q.kernel_lost_events(), None);
    q.kernel_end.insert(0, [Some(12), Some(0), Some(0)]);
    assert_eq!(q.kernel_lost_events(), Some(2));
    q.kernel_end.insert(1, [Some(0), Some(0), Some(0)]);
    assert_eq!(q.kernel_lost_events(), None);
}
