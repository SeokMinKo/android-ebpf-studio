//! Offline validation utility. Desktop capture uses the same native Projection.
use android_ebpf_protocol::*;
use android_ebpf_studio::{perfetto, perfetto_projection::Projection};
use std::io::Write;
fn main() -> anyhow::Result<()> {
    let mut args = std::env::args_os().skip(1);
    let source = std::path::PathBuf::from(args.next().ok_or_else(|| {
        anyhow::anyhow!("usage: perfetto_project input.pftrace new-output.ndjson")
    })?);
    let output = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("New output path required"))?;
    let started = std::time::Instant::now();
    let decoded = perfetto::decode(std::io::BufReader::new(std::fs::File::open(&source)?));
    let analysis = perfetto::analyze(&decoded);
    let projection = Projection::new(&decoded);
    let mut out = std::io::BufWriter::new(
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)?,
    );
    write_record(
        &mut out,
        &WireRecord::SourceInfo {
            schema_version: SCHEMA_VERSION,
            source: "perfetto".into(),
            status: format!(
                "Offline Perfetto projection · {} completions · FilePath unresolved",
                analysis.completions.len()
            ),
            metadata: serde_json::json!({"stage":"complete","offline_validation":true,"quality":decoded.quality,"raw_trace":source,"block_records":decoded.events.len()}),
        },
    )?;
    let mut engine = AnalysisEngine::new();
    for (i, o) in analysis.completions.iter().enumerate() {
        let event = StorageEvent::ObservedBlockCompletion(projection.completion(o)?);
        write_record(
            &mut out,
            &WireRecord::Event {
                schema_version: SCHEMA_VERSION,
                sequence: i as u64 + 1,
                event: event.clone(),
            },
        )?;
        engine.ingest(event);
    }
    let count = analysis.completions.len() as u64;
    write_record(
        &mut out,
        &WireRecord::Footer {
            schema_version: SCHEMA_VERSION,
            events_seen: count,
            events_persisted: count,
            events_dropped: 0,
            events_rejected: 0,
            graceful: Some(!decoded.quality.truncated && !decoded.quality.projection_limited),
        },
    )?;
    out.flush()?;
    println!(
        "{}",
        serde_json::to_string_pretty(
            &serde_json::json!({"summary":engine.summary(),"decode_project_write_ms":started.elapsed().as_secs_f64()*1000.0})
        )?
    );
    Ok(())
}
