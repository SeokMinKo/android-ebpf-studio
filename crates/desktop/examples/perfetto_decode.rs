use android_ebpf_studio::perfetto;
fn main() -> anyhow::Result<()> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: perfetto_decode trace.pftrace [output.json]"))?;
    let started = std::time::Instant::now();
    let decoded = perfetto::decode(std::io::BufReader::new(std::fs::File::open(&path)?));
    let analysis = perfetto::analyze(&decoded);
    let elapsed = started.elapsed().as_secs_f64() * 1000.0;
    let path = path.to_string_lossy();
    let result = serde_json::json!({"source":path,"decode_and_analyze_ms":elapsed,"quality":decoded.quality,"events":decoded.events.len(),"process_metadata":decoded.processes.len(),"completions":analysis.completions.len(),"probable_timing":analysis.completions.iter().filter(|v|v.device_latency_ns.is_some()).count(),"read_bytes":analysis.completions.iter().filter(|v|v.rwbs.starts_with('R')).map(|v|v.bytes).sum::<u64>(),"write_bytes":analysis.completions.iter().filter(|v|v.rwbs.starts_with('W')).map(|v|v.bytes).sum::<u64>()});
    println!("{}", serde_json::to_string_pretty(&result)?);
    if let Some(output) = std::env::args_os().nth(2) {
        let json = serde_json::json!({"summary":result,"decoded":decoded,"analysis":analysis});
        serde_json::to_writer_pretty(
            std::io::BufWriter::new(std::fs::File::create(output)?),
            &json,
        )?;
    }
    Ok(())
}
