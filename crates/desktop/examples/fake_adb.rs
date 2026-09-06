//! Host-only ADB transport fixture. Never represents physical-device evidence.
use android_ebpf_protocol::{SCHEMA_VERSION, WireRecord};
use std::io::{BufRead, Write};

fn emit(record: WireRecord) {
    println!("{}", serde_json::to_string(&record).unwrap());
    std::io::stdout().flush().unwrap();
}
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|v| v == "devices") {
        println!(
            "List of devices attached\nroot-phone device model:Fixture_A\nsu-phone device model:Fixture_B"
        );
        return;
    }
    let serial = args.get(1).map(String::as_str).unwrap_or("");
    let command = args.get(3..).unwrap_or_default().join(" ");
    if args.get(2).is_some_and(|v| v == "push") {
        println!("1 file pushed");
        return;
    }
    if command.contains("'id' '-u'") || command.contains("id") && command.contains("-u") {
        println!(
            "{}",
            if serial == "root-phone" || command.starts_with("su ") {
                "0"
            } else {
                "2000"
            }
        );
        return;
    }
    if command.contains("--query") && serial == "root-phone" {
        println!("Perfetto v51.2 fixture\nlinux.ftrace");
    } else if command.contains("ro.product.cpu.abi") {
        println!(
            "{}",
            if serial == "counter-phone" {
                "x86_64"
            } else {
                "arm64-v8a"
            }
        );
    } else if command.contains("ro.product.model") {
        println!("fixture-{serial}");
    } else if command.contains("ro.build.version.release") {
        println!("16");
    } else if command.contains("ro.build.fingerprint") {
        println!("fixture/{serial}/build");
    } else if command.contains("diskstats") && command.contains("boot_id") {
        if serial == "disconnect-phone" {
            std::process::exit(1);
        }
        println!("boot-{serial}\n8 1 sda1 10 0 80 1 20 0 160 2 0 3 4");
    } else if command.contains("boot_id") {
        println!("boot-{serial}");
    } else if command.contains("uname") {
        println!("6.6-fixture");
    } else if command.contains("mountinfo") {
        println!("1 0 8:1 / /data rw - ext4 /dev/block/sda1 rw");
    } else if command.contains("filesystems") {
        println!("ext4");
    } else if command.contains("partitions") {
        println!("8 1 1024 sda1");
    } else if command.contains("diskstats") {
        if serial == "disconnect-phone" {
            std::process::exit(1);
        }
        println!("8 1 sda1 10 0 80 1 20 0 160 2 0 3 4");
    } else if command.contains("'find'") {
        println!("/sys/kernel/tracing/events/block");
    } else if command.contains("'capture'") {
        emit(WireRecord::Hello {
            schema_version: SCHEMA_VERSION,
            agent_version: "fixture".into(),
            boot_id: format!("boot-{serial}"),
            kernel_release: "fixture".into(),
        });
        // Readiness is not fabricated; test records arrive before and after EOF.
        emit(WireRecord::Health {
            schema_version: SCHEMA_VERSION,
            emitted_events: 0,
            kernel_drops: Some(0),
            userspace_drops: 0,
            probe_health: Default::default(),
            correlation_ambiguous: 0,
            correlation_expired: 0,
            key_reused: 0,
        });
        if serial == "disconnect-phone" {
            std::process::exit(1);
        }
        for line in std::io::stdin().lock().lines() {
            if line.is_err() {
                break;
            }
        }
        // This final snapshot must survive Stop and appear before Ended.
        emit(WireRecord::Health {
            schema_version: SCHEMA_VERSION,
            emitted_events: 123,
            kernel_drops: Some(7),
            userspace_drops: 0,
            probe_health: Default::default(),
            correlation_ambiguous: 0,
            correlation_expired: 0,
            key_reused: 0,
        });
        emit(WireRecord::Footer {
            schema_version: SCHEMA_VERSION,
            events_seen: 0,
            events_persisted: 0,
            events_dropped: 0,
            events_rejected: 0,
            graceful: Some(true),
        });
    }
}
