use android_ebpf_studio::{adb::AdbClient, perfetto, perfetto_capture::PerfettoCapture};
fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    anyhow::ensure!(
        args.len() == 4,
        "usage: perfetto_capture adb_path serial new_output_directory"
    );
    let started = std::time::Instant::now();
    let capture = PerfettoCapture::start(
        AdbClient::new(&args[1]),
        &args[2],
        std::path::Path::new(&args[3]),
        30_000,
    )?;
    println!(
        "READY pid={:?} start_ms={}",
        capture.owner.pid,
        started.elapsed().as_millis()
    );
    std::thread::sleep(std::time::Duration::from_secs(5));
    let stopped = std::time::Instant::now();
    let decoded = capture.stop_and_pull()?;
    let analysis = perfetto::analyze(&decoded);
    let report = serde_json::json!({"owner":capture.owner,"stop_pull_analysis_ms":stopped.elapsed().as_secs_f64()*1000.0,"quality":decoded.quality,"events":decoded.events.len(),"completions":analysis.completions.len(),"probable_timings":analysis.completions.iter().filter(|o|o.device_latency_ns.is_some()).count(),"read_bytes":analysis.completions.iter().filter(|o|o.rwbs.starts_with('R')).map(|o|o.bytes).sum::<u64>(),"write_bytes":analysis.completions.iter().filter(|o|o.rwbs.starts_with('W')).map(|o|o.bytes).sum::<u64>()});
    std::fs::write(
        std::path::Path::new(&args[3]).join("capture-validation.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
