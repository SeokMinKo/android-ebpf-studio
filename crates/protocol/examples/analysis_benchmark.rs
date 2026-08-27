use std::{env, hint::black_box, time::Instant};

use android_ebpf_protocol::{AnalysisEngine, BlockComplete, BlockIssue, IoOperation, StorageEvent};

fn main() {
    let events = env::args()
        .nth(1)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(1_000_000);
    let mut engine = AnalysisEngine::new();
    let ingest_started = Instant::now();
    for request_id in 0..events {
        let issue_ts = request_id.saturating_mul(10_000);
        let latency = if request_id % 100 == 0 {
            8_000_000
        } else {
            200_000 + request_id % 32 * 1_000
        };
        let operation = if request_id % 4 == 0 {
            IoOperation::Write
        } else {
            IoOperation::Read
        };
        engine.ingest(StorageEvent::BlockIssue(BlockIssue {
            ts_ns: issue_ts,
            request_id,
            device_major: 8,
            device_minor: 0,
            sector: request_id.saturating_mul(8),
            sectors: 8,
            bytes: 4096,
            operation,
            pid: 10_000 + (request_id % 64) as u32,
            tid: 20_000 + (request_id % 256) as u32,
            cpu: (request_id % 8) as u32,
            comm: format!("bench-{}", request_id % 64),
        }));
        engine.ingest(StorageEvent::BlockComplete(BlockComplete {
            ts_ns: issue_ts.saturating_add(latency),
            request_id,
            device_major: 8,
            device_minor: 0,
            status: 0,
        }));
    }
    let ingest_elapsed = ingest_started.elapsed();
    let summary_started = Instant::now();
    let summary = black_box(engine.summary());
    let summary_elapsed = summary_started.elapsed();
    let graph_started = Instant::now();
    let graph_count = black_box(engine.transactions().len());
    let graph_elapsed = graph_started.elapsed();

    println!(
        "source_requests={events} retained_requests={} completed={} ingest_ms={} summary_ms={} graph_ms={} graphs={graph_count}",
        engine.completed_ios().len(),
        summary.completed_ios,
        ingest_elapsed.as_millis(),
        summary_elapsed.as_millis(),
        graph_elapsed.as_millis(),
    );
}
