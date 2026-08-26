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
        "start_ts_ns",
        "request_id",
        "device",
        "sector",
        "bytes",
        "operation",
        "pid",
        "tid",
        "comm",
        "fd",
        "path",
        "attribution",
        "requested_bytes",
        "completed_bytes",
        "status",
    ])?;
    for event in loaded.events {
        match &event {
            StorageEvent::BlockIssue(issue) => writer.write_record([
                "block_issue".to_owned(),
                issue.ts_ns.to_string(),
                String::new(),
                issue.request_id.to_string(),
                format!("{}:{}", issue.device_major, issue.device_minor),
                issue.sector.to_string(),
                issue.bytes.to_string(),
                format!("{:?}", issue.operation).to_lowercase(),
                issue.pid.to_string(),
                issue.tid.to_string(),
                issue.comm.clone(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            ])?,
            StorageEvent::BlockInsert(insert) => writer.write_record([
                "block_insert".to_owned(),
                insert.ts_ns.to_string(),
                String::new(),
                insert.request_id.to_string(),
                format!("{}:{}", insert.device_major, insert.device_minor),
                insert.sector.to_string(),
                insert.bytes.to_string(),
                format!("{:?}", insert.operation).to_lowercase(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            ])?,
            StorageEvent::BlockComplete(complete) => writer.write_record([
                "block_complete".to_owned(),
                complete.ts_ns.to_string(),
                String::new(),
                complete.request_id.to_string(),
                format!("{}:{}", complete.device_major, complete.device_minor),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                complete.status.to_string(),
            ])?,
            StorageEvent::FileIo(file) => writer.write_record([
                "file_io".to_owned(),
                file.end_ts_ns.to_string(),
                file.start_ts_ns.to_string(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                format!("{:?}", file.operation).to_lowercase(),
                file.pid.to_string(),
                file.tid.to_string(),
                file.comm.clone(),
                file.fd.to_string(),
                file.path.clone().unwrap_or_default(),
                format!("{:?}", file.confidence).to_lowercase(),
                file.requested_bytes.to_string(),
                file.completed_bytes.to_string(),
                String::new(),
            ])?,
            StorageEvent::Pipeline(stage) => writer.write_record([
                format!("pipeline_{:?}", stage.layer).to_lowercase(),
                stage.end_ts_ns.unwrap_or(stage.ts_ns).to_string(),
                stage.ts_ns.to_string(),
                stage
                    .correlation_id
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
                String::new(),
                stage
                    .sector
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
                stage
                    .bytes
                    .map(|value| value.to_string())
                    .unwrap_or_default(),
                String::new(),
                stage.pid.to_string(),
                stage.tid.to_string(),
                stage.name.clone(),
                String::new(),
                String::new(),
                format!("{:?}", stage.confidence).to_lowercase(),
                String::new(),
                String::new(),
                String::new(),
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
        ("sequential_ios", summary.sequential_ios.to_string()),
        ("random_ios", summary.random_ios.to_string()),
        ("small_ios", summary.small_ios.to_string()),
        ("large_ios", summary.large_ios.to_string()),
        ("logging_ns", summary.logging_ns.to_string()),
        ("busy_ns", summary.busy_ns.to_string()),
        ("idle_ns", summary.idle_ns.to_string()),
        ("file_ios", summary.file_ios.to_string()),
        (
            "attributed_file_ios",
            summary.attributed_file_ios.to_string(),
        ),
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
