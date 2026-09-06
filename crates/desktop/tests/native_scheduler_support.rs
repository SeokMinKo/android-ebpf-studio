// Exercise the platform-independent collector modules on the host as well as
// cross-compiling the Android collector. This does not claim kernel acceptance.
#[path = "../../android-agent/src/scheduler_stats.rs"]
mod scheduler_stats;
#[path = "../../android-agent/src/scheduler_wait.rs"]
mod scheduler_wait;
#[path = "../../android-agent/src/trace_format.rs"]
#[allow(dead_code)]
mod trace_format;

#[test]
fn scheduler_layout_validates_payload_identity_sizes_and_fixed_comm() {
    let valid = "field:int common_pid; offset:4; size:4; signed:1;\nfield:char comm[16]; offset:8; size:16; signed:1;\nfield:pid_t pid; offset:24; size:4; signed:1;\nfield:u64 delay; offset:32; size:8; signed:0;\n";
    let layout = trace_format::parse_scheduler_wait_layout(valid).unwrap();
    assert_eq!(
        (layout.pid_offset, layout.delay_offset, layout.comm_offset),
        (24, 32, 8)
    );
    for invalid in [
        valid.replace("size:8;", "size:4;"),
        valid.replace("field:pid_t pid;", "field:pid_t unknown;"),
        valid.replace(
            "field:char comm[16]; offset:8; size:16;",
            "field:__data_loc char[] comm; offset:8; size:4;",
        ),
        valid.replace("offset:32;", "offset:65535;"),
    ] {
        assert!(trace_format::parse_scheduler_wait_layout(&invalid).is_err());
    }
}

#[test]
fn scheduler_filter_never_substitutes_observer_pid_or_block_fields() {
    use android_ebpf_types::*;
    let supported = RawFilterConfig {
        mode: MODE_BALANCED,
        tid_count: 1,
        ..Default::default()
    };
    assert!(scheduler_filter_supported(&supported));
    for unsupported in [
        RawFilterConfig {
            mode: MODE_BASIC,
            ..supported
        },
        RawFilterConfig {
            pid_count: 1,
            ..supported
        },
        RawFilterConfig {
            uid_count: 1,
            ..supported
        },
        RawFilterConfig {
            device_count: 1,
            ..supported
        },
        RawFilterConfig {
            operation_count: 1,
            ..supported
        },
        RawFilterConfig {
            min_bytes: 1,
            ..supported
        },
        RawFilterConfig {
            max_bytes: 4096,
            ..supported
        },
    ] {
        assert!(!scheduler_filter_supported(&unsupported));
    }
}
