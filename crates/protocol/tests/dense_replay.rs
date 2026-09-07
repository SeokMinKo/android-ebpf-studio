//! Opt-in regression against an immutable physical NDJSON and pre-change graphs.
use android_ebpf_protocol::{AnalysisEngine, FilePathCoverageEngine, WireRecord};
use std::{
    fs,
    io::{BufRead, BufReader},
    path::PathBuf,
    time::{Duration, Instant},
};

fn records() -> impl Iterator<Item = WireRecord> {
    let path = std::env::var("DENSE_REPLAY_NDJSON").expect("set DENSE_REPLAY_NDJSON");
    BufReader::new(fs::File::open(path).unwrap())
        .lines()
        .map(|line| serde_json::from_str(&line.unwrap()).unwrap())
}

#[test]
#[ignore = "requires physical capture and pre-change graph references; run --release"]
fn dense_replay_preserves_200_graphs_within_two_seconds() {
    let reference =
        PathBuf::from(std::env::var("DENSE_REPLAY_REFERENCE").expect("set DENSE_REPLAY_REFERENCE"));
    let mut engine = AnalysisEngine::new();
    for record in records() {
        if let WireRecord::Event { event, .. } = record {
            engine.ingest(event);
        }
    }
    assert!(engine.completed_ios().len() >= 200);
    let start = Instant::now();
    for (index, io) in engine.completed_ios().iter().take(200).enumerate() {
        let graph = engine.transaction_for(io);
        let actual = serde_json::to_vec(&graph).unwrap();
        assert_eq!(
            actual,
            fs::read(reference.join(format!("{index}.json"))).unwrap(),
            "graph {index}"
        );
    }
    let elapsed = start.elapsed();
    eprintln!("200 physical graphs: {elapsed:?}");
    assert!(
        elapsed < Duration::from_secs(2),
        "200 graphs exceeded 2 seconds: {elapsed:?}"
    );
}

#[test]
#[ignore = "requires physical capture; run --release"]
fn dense_whole_source_coverage_finishes_within_thirty_seconds() {
    let mut engine = FilePathCoverageEngine::default();
    for record in records() {
        if let WireRecord::Event { event, .. } = record {
            engine.ingest(&event);
        }
    }
    let start = Instant::now();
    let coverage = engine.finish();
    let elapsed = start.elapsed();
    eprintln!(
        "physical coverage: {elapsed:?} {}",
        serde_json::to_string(&coverage).unwrap()
    );
    assert_eq!(coverage.completion_records(), 12_444);
    assert_eq!(coverage.unmatched_completions, 56);
    assert!(
        elapsed < Duration::from_secs(30),
        "coverage exceeded 30 seconds: {elapsed:?}"
    );
}
