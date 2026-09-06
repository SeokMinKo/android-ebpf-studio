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
        let mut fields = vec!["0".to_owned(); 20];
        fields[0] = "S".into();
        fields[19] = cfg["ticks"].as_u64().unwrap().to_string();
        println!("42 (perfetto) {}", fields.join(" "));
    } else if cmd.contains("/cmdline") {
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
