//! Host-only deterministic recovery fixture. Never talks to an Android device.
use std::io::Write;
fn main() -> anyhow::Result<()> {
    let home = std::env::current_exe()?.parent().unwrap().to_owned();
    let cfg: serde_json::Value =
        serde_json::from_slice(&std::fs::read(home.join("fixture.json"))?)?;
    let args: Vec<_> = std::env::args().skip(1).collect();
    let mut log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(home.join("commands.jsonl"))?;
    writeln!(log, "{}", serde_json::to_string(&args)?)?;
    anyhow::ensure!(
        args.first().map(String::as_str) == Some("-s")
            && args.get(1).map(String::as_str) == cfg["serial"].as_str(),
        "wrong device binding"
    );
    if cfg["capture_test"] == true && capture_command(&home, &cfg, &args)? {
        return Ok(());
    }
    if args.get(2).map(String::as_str) == Some("pull") {
        anyhow::ensure!(cfg["fail_pull"] != true, "simulated disconnect during pull");
        anyhow::ensure!(
            args.get(3).map(String::as_str) == cfg["remote_trace"].as_str(),
            "foreign raw trace"
        );
        std::fs::copy(home.join("source.pftrace"), args.get(4).unwrap())?;
        return Ok(());
    }
    let cmd = args[2..].join(" ");
    if cmd.contains("/proc/sys/kernel/random/boot_id") {
        println!("{}", cfg["boot"].as_str().unwrap());
    } else if cmd.contains("if test -e /proc/") {
        println!(
            "{}",
            if home.join("stopped").exists() {
                "absent"
            } else {
                "present"
            }
        );
    } else if cmd.contains("/stat") {
        if cfg["fail_first_stat"] == true && !home.join("stat-failed").exists() {
            std::fs::write(home.join("stat-failed"), b"failed")?;
            anyhow::bail!("fixture transient process lifetime read failure");
        }
        let count_path = home.join("stat-count");
        let count = std::fs::read_to_string(&count_path)
            .ok()
            .and_then(|n| n.parse::<u64>().ok())
            .unwrap_or(0);
        std::fs::write(count_path, (count + 1).to_string())?;
        let mut fields = vec!["0".to_owned(); 20];
        fields[0] = if cfg["vary_state"] == true && count % 2 == 1 {
            "R"
        } else {
            "S"
        }
        .into();
        fields[19] = cfg["ticks"].as_u64().unwrap().to_string();
        println!("42 (perfetto) {}", fields.join(" "));
    } else if cmd.contains("/cmdline") {
        if cfg["fail_first_cmdline"] == true && !home.join("cmdline-failed").exists() {
            std::fs::write(home.join("cmdline-failed"), b"failed")?;
            anyhow::bail!("fixture transient process identity read failure");
        }
        if cfg["foreign_command"] == true {
            print!(
                "perfetto\0/data/misc/perfetto-configs/foreign.pbtxt\0/data/misc/perfetto-traces/foreign.pftrace\0"
            );
            return Ok(());
        }
        print!(
            "perfetto\0{}\0{}\0",
            cfg["remote_config"].as_str().unwrap(),
            cfg["remote_trace"].as_str().unwrap()
        );
    } else if cmd.contains("kill") {
        std::fs::write(home.join("stopped"), b"stopped")?;
    } else {
        anyhow::bail!("unexpected fake ADB command: {cmd}");
    }
    Ok(())
}

fn capture_command(
    home: &std::path::Path,
    cfg: &serde_json::Value,
    args: &[String],
) -> anyhow::Result<bool> {
    let cmd = args[2..].join(" ");
    if args.get(2).is_some_and(|s| s == "push") {
        return Ok(true);
    }
    if cmd.contains("'pidof' 'perfetto'") {
        anyhow::ensure!(
            cfg["fail_enumerate"] != true,
            "fixture disconnected during process enumeration"
        );
        if cfg["remote_trace"].as_str().is_some() && !home.join("stopped").exists() {
            println!(
                "{}",
                if cfg["ambiguous"] == true {
                    "42 43"
                } else {
                    "42"
                }
            );
        }
    } else if cmd.contains("'test' '-f'") && cmd.contains("/data/misc/perfetto-traces/") {
        if cfg["remote_trace"].as_str().is_none() {
            std::process::exit(1);
        }
    } else if cmd.contains("'id' '-u'") {
        println!("0");
    } else if cmd.contains("--query") {
        anyhow::ensure!(cfg["perfetto"] == true, "Perfetto service unavailable");
        println!("Perfetto v51.2 fixture\nlinux.ftrace");
    } else if cmd.contains("getprop") {
        println!(
            "{}",
            if cmd.contains("ro.product.cpu.abi") {
                "arm64-v8a"
            } else if cmd.contains("ro.product.model") {
                "fixture"
            } else if cmd.contains("ro.build.version.release") {
                "16"
            } else {
                "fixture/build"
            }
        );
    } else if cmd.contains("boot_id") {
        println!(
            "{}",
            if cfg["reboot_after_failure"] == true && home.join("agent-failed").exists() {
                "boot-new"
            } else {
                cfg["boot"].as_str().unwrap()
            }
        );
    } else if cmd.contains("uname") {
        println!("6.6-fixture");
    } else if cmd.contains("mountinfo") {
        println!("1 0 8:1 / /data rw - ext4 /dev/block/sda1 rw");
    } else if cmd.contains("filesystems") {
        println!("ext4");
    } else if cmd.contains("partitions") {
        println!("8 1 1024 sda1");
    } else if cmd.contains("diskstats") {
        println!("8 1 sda1 10 0 80 1 20 0 160 2 0 3 4");
    } else if cmd.contains("'test'") || cmd.contains("'chmod'") || cmd.contains("'mkdir'") {
        // Known preflight/deployment commands succeed in this rooted fixture.
    } else if cmd.contains("'find'") {
        println!("/sys/kernel/tracing/events/block");
    } else if cmd.contains("'capture'") {
        use android_ebpf_protocol::{SCHEMA_VERSION, WireRecord};
        match cfg["agent_behavior"].as_str().unwrap_or("fail") {
            "empty-success" => return Ok(true),
            "data-then-fail" => println!(
                "{}",
                serde_json::to_string(&WireRecord::Event {
                    schema_version: SCHEMA_VERSION,
                    sequence: 1,
                    event: android_ebpf_protocol::StorageEvent::BlockIssue(
                        android_ebpf_protocol::BlockIssue {
                            ts_ns: 1,
                            request_id: 42,
                            device_major: 8,
                            device_minor: 0,
                            sector: 32,
                            sectors: 8,
                            bytes: 4096,
                            operation: android_ebpf_protocol::IoOperation::Read,
                            pid: 20,
                            tid: 20,
                            cpu: 0,
                            comm: "fixture".into(),
                        }
                    ),
                })?
            ),
            "ready-then-fail" => println!(
                "{}",
                serde_json::to_string(&WireRecord::Capabilities {
                    schema_version: SCHEMA_VERSION,
                    capabilities: serde_json::from_value(serde_json::json!({
                        "bpf_syscall":true,"btf":true,"ring_buffer":true,"block_issue":true,"block_complete":true
                    }))?,
                })?
            ),
            "stop-then-fail" => {
                println!(
                    "{}",
                    serde_json::to_string(&WireRecord::Health {
                        schema_version: SCHEMA_VERSION,
                        emitted_events: 0,
                        kernel_drops: Some(0),
                        userspace_drops: 0,
                        probe_health: Default::default(),
                        correlation_ambiguous: 0,
                        correlation_expired: 0,
                        key_reused: 0
                    })?
                );
                std::io::stdout().flush()?;
                use std::io::Read;
                std::io::stdin().read_to_end(&mut Vec::new())?;
            }
            _ => {}
        }
        std::io::stdout().flush()?;
        std::fs::write(home.join("agent-failed"), b"failed")?;
        anyhow::bail!("fixture eBPF verifier rejected program");
    } else if cmd.contains("--background-wait") {
        anyhow::ensure!(cfg["fail_start"] != true, "fixture Perfetto start rejected");
        let parts: Vec<_> = cmd.split('\'').collect();
        let config = parts
            .iter()
            .find(|p| p.starts_with("/data/misc/perfetto-configs/"))
            .unwrap();
        let trace = parts
            .iter()
            .find(|p| p.starts_with("/data/misc/perfetto-traces/"))
            .unwrap();
        let mut updated = cfg.clone();
        updated["remote_config"] = (*config).into();
        updated["remote_trace"] = (*trace).into();
        std::fs::write(home.join("fixture.json"), serde_json::to_vec(&updated)?)?;
        if cfg["omit_pid"] != true {
            println!("42");
            std::io::stdout().flush()?;
        }
        anyhow::ensure!(
            cfg["error_after_launch"] != true,
            "fixture data source readiness timeout after launch"
        );
    } else if cmd.contains("'stat' '-c'") {
        println!("1000");
    } else {
        return Ok(false);
    }
    Ok(true)
}
