//! Opt-in stage timings for an existing raw trace. Does not start ADB or modify input.
use android_ebpf_protocol::{SCHEMA_VERSION, StorageEvent, WireRecord, write_record};
use android_ebpf_studio::{perfetto, perfetto_projection::Projection};
use std::{io::BufReader, time::Instant};

fn main() -> anyhow::Result<()> {
    let source = std::env::args_os()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("Usage: perfetto_benchmark <saved-capture.pftrace>"))?;
    let before = std::fs::metadata(&source)?;
    let start = Instant::now();
    let trace = perfetto::decode(BufReader::new(std::fs::File::open(&source)?));
    let decoded = Instant::now();
    let analysis = perfetto::analyze(&trace);
    let correlated = Instant::now();
    let projection = Projection::new(&trace);
    let indexed = Instant::now();
    let mut bytes = 0_u64;
    for observation in &analysis.completions {
        bytes += u64::from(projection.completion(observation)?.issue.bytes);
    }
    let projected = Instant::now();
    let mut sink = std::io::sink();
    for (index, observation) in analysis.completions.iter().enumerate() {
        write_record(
            &mut sink,
            &WireRecord::Event {
                schema_version: SCHEMA_VERSION,
                sequence: index as u64 + 1,
                event: StorageEvent::ObservedBlockCompletion(projection.completion(observation)?),
            },
        )?;
    }
    let serialized = Instant::now();
    let after = std::fs::metadata(&source)?;
    anyhow::ensure!(
        before.len() == after.len() && before.modified()? == after.modified()?,
        "Trace changed during benchmark"
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "source_bytes":before.len(),"block_records":trace.events.len(),
            "completion_observations":analysis.completions.len(),"completion_bytes":bytes,
            "decode_ms":(decoded-start).as_secs_f64()*1000.0,
            "correlate_ms":(correlated-decoded).as_secs_f64()*1000.0,
            "index_ms":(indexed-correlated).as_secs_f64()*1000.0,
            "project_ms":(projected-indexed).as_secs_f64()*1000.0,
            "project_and_serialize_to_sink_ms":(serialized-projected).as_secs_f64()*1000.0,
            "quality":trace.quality,
            "scope":"Host stage timings only; excludes ADB, GUI ingestion, disk writes and fsync. Serialization repeats projection; do not add both projection timings."
        }))?
    );
    Ok(())
}
