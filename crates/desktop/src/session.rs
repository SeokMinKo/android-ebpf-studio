use std::{
    fs::File,
    io::{BufReader, BufWriter, Write},
    path::{Path, PathBuf},
};

use android_ebpf_protocol::{
    AnalysisEngine, AnalysisSummary, SessionError, SessionReader, StorageEvent, WireRecord,
    write_record,
};

pub struct SessionWriter {
    output: BufWriter<File>,
    pub persisted: u64,
    pub rejected: u64,
}

impl SessionWriter {
    pub fn create(path: &Path) -> Result<Self, SessionError> {
        Ok(Self {
            output: BufWriter::new(File::create(path)?),
            persisted: 0,
            rejected: 0,
        })
    }

    pub fn append(&mut self, record: &WireRecord) -> Result<(), SessionError> {
        write_record(&mut self.output, record)?;
        if matches!(record, WireRecord::Event { .. }) {
            self.persisted += 1;
        }
        Ok(())
    }

    pub fn finish(mut self, footer: &WireRecord) -> Result<(), SessionError> {
        self.append(footer)?;
        self.output.flush()?;
        Ok(())
    }
}

pub fn load_analysis(path: &Path) -> Result<(AnalysisEngine, u64), SessionError> {
    let loaded = SessionReader::default().read(BufReader::new(File::open(path)?))?;
    let mut engine = AnalysisEngine::new();
    for event in loaded.events {
        engine.ingest(event);
    }
    Ok((engine, loaded.rejected_lines))
}

pub fn export_csv(session_path: &Path, events_path: &Path) -> anyhow::Result<PathBuf> {
    let loaded = SessionReader::default().read(BufReader::new(File::open(session_path)?))?;
    let mut engine = AnalysisEngine::new();
    let mut writer = csv::Writer::from_path(events_path)?;
    writer.write_record([
        "kind",
        "ts_ns",
        "request_id",
        "device",
        "sector",
        "bytes",
        "operation",
        "pid",
        "comm",
        "status",
    ])?;
    for event in loaded.events {
        match &event {
            StorageEvent::BlockIssue(issue) => writer.write_record([
                "block_issue".to_owned(),
                issue.ts_ns.to_string(),
                issue.request_id.to_string(),
                format!("{}:{}", issue.device_major, issue.device_minor),
                issue.sector.to_string(),
                issue.bytes.to_string(),
                format!("{:?}", issue.operation).to_lowercase(),
                issue.pid.to_string(),
                issue.comm.clone(),
                String::new(),
            ])?,
            StorageEvent::BlockComplete(complete) => writer.write_record([
                "block_complete".to_owned(),
                complete.ts_ns.to_string(),
                complete.request_id.to_string(),
                format!("{}:{}", complete.device_major, complete.device_minor),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                complete.status.to_string(),
            ])?,
        }
        engine.ingest(event);
    }
    writer.flush()?;

    let summary_path = events_path.with_file_name(format!(
        "{}_summary.csv",
        events_path
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("session")
    ));
    write_summary(&summary_path, &engine.summary())?;
    Ok(summary_path)
}

fn write_summary(path: &Path, summary: &AnalysisSummary) -> anyhow::Result<()> {
    let mut writer = csv::Writer::from_path(path)?;
    writer.write_record(["metric", "value"])?;
    for (metric, value) in [
        ("issued_ios", summary.issued_ios.to_string()),
        ("completed_ios", summary.completed_ios.to_string()),
        ("read_bytes", summary.read_bytes.to_string()),
        ("write_bytes", summary.write_bytes.to_string()),
        ("max_queue_depth", summary.max_queue_depth.to_string()),
        (
            "p50_latency_ns",
            summary.p50_latency_ns.unwrap_or_default().to_string(),
        ),
        (
            "p95_latency_ns",
            summary.p95_latency_ns.unwrap_or_default().to_string(),
        ),
        (
            "p99_latency_ns",
            summary.p99_latency_ns.unwrap_or_default().to_string(),
        ),
    ] {
        writer.write_record([metric, &value])?;
    }
    writer.flush()?;
    Ok(())
}
