use std::{
    fs::File,
    io::{BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    sync::mpsc,
    thread,
};

use android_ebpf_protocol::{
    AggregateSnapshot, AnalysisEngine, AnalysisSummary, HeavyHitterSnapshot, IoOperation,
    ProbeCapabilities, SegmentRecord, SessionError, SessionReader, StackFingerprintRecord,
    StorageEvent, TriggerRecord, WireRecord, write_record,
};

pub struct SessionWriter {
    output: BufWriter<File>,
    pub persisted: u64,
    pub rejected: u64,
}

enum PersistCommand {
    Record(Box<WireRecord>),
    Finish {
        events_seen: u64,
        events_rejected: u64,
        graceful: bool,
    },
}

pub struct AsyncSessionWriter {
    tx: mpsc::SyncSender<PersistCommand>,
    worker: Option<thread::JoinHandle<Result<(), SessionError>>>,
}

impl AsyncSessionWriter {
    pub fn create(path: &Path) -> Result<Self, SessionError> {
        // Open synchronously so Start Capture reports path/permission failures
        // before any measurement begins. Serialization and disk writes happen
        // exclusively on the worker after this point.
        let writer = SessionWriter::create(path)?;
        let (tx, rx) = mpsc::sync_channel::<PersistCommand>(16_384);
        let worker = thread::spawn(move || {
            let mut writer = writer;
            while let Ok(command) = rx.recv() {
                match command {
                    PersistCommand::Record(record) => {
                        writer.append(&record)?;
                    }
                    PersistCommand::Finish {
                        events_seen,
                        events_rejected,
                        graceful,
                    } => {
                        let rejected = events_rejected;
                        let persisted = writer.persisted;
                        let footer = WireRecord::Footer {
                            schema_version: android_ebpf_protocol::SCHEMA_VERSION,
                            events_seen,
                            events_persisted: persisted,
                            events_dropped: events_seen.saturating_sub(persisted + rejected),
                            events_rejected: rejected,
                            graceful: Some(graceful),
                        };
                        return writer.finish(&footer);
                    }
                }
            }
            Ok(())
        });
        Ok(Self {
            tx,
            worker: Some(worker),
        })
    }

    pub fn append(&self, record: WireRecord) -> Result<(), SessionError> {
        self.tx
            .try_send(PersistCommand::Record(Box::new(record)))
            .map_err(|_| {
                SessionError::Io(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "session writer unavailable or backlog full; free disk space and retry after saving partial data",
                ))
            })
    }

    pub fn finish(
        mut self,
        events_seen: u64,
        events_rejected: u64,
        graceful: bool,
    ) -> Result<(), SessionError> {
        self.tx
            .send(PersistCommand::Finish {
                events_seen,
                events_rejected,
                graceful,
            })
            .map_err(|_| {
                SessionError::Io(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "session writer stopped",
                ))
            })?;
        self.worker
            .take()
            .expect("session writer worker exists")
            .join()
            .map_err(|_| SessionError::Io(std::io::Error::other("session writer panicked")))?
    }
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
        self.output.get_ref().sync_all()?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct LoadedAnalysis {
    pub activity: std::sync::Arc<crate::host_bw::ActivityTimeline>,
    pub source_start_ns: u64,
    pub source_end_ns: u64,
    pub source_completed_ios: u64,
    pub window_ns: Option<(u64, u64)>,
    pub load_elapsed_ms: f64,
    pub loss_status: String,
    pub source_info: Vec<WireRecord>,
    pub disk_stats: Vec<WireRecord>,
    pub engine: AnalysisEngine,
    pub accepted_events: u64,
    pub rejected_lines: u64,
    pub integrity_ok: Option<bool>,
    pub graceful: Option<bool>,
    pub capabilities: Option<ProbeCapabilities>,
    pub latest_aggregate: Option<AggregateSnapshot>,
    pub heavy_hitters: Vec<HeavyHitterSnapshot>,
    pub triggers: Vec<TriggerRecord>,
    pub segments: Vec<SegmentRecord>,
    pub stack_fingerprints: Vec<StackFingerprintRecord>,
}

pub fn load_analysis(path: &Path) -> Result<LoadedAnalysis, SessionError> {
    load_analysis_window(path, None, None)
}

/// Reads the original stream without materializing every raw event. A selected
/// window is replayed in two passes: original block ordering, then its evidence.
pub fn load_analysis_window(
    path: &Path,
    window: Option<(u64, u64)>,
    cancel: Option<&std::sync::atomic::AtomicBool>,
) -> Result<LoadedAnalysis, SessionError> {
    let started = std::time::Instant::now();
    let before = std::fs::metadata(path)?;
    let check_cancel = || -> Result<(), SessionError> {
        if cancel.is_some_and(|v| v.load(std::sync::atomic::Ordering::Relaxed)) {
            Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "Reanalysis cancelled; previous analysis preserved",
            )
            .into())
        } else {
            Ok(())
        }
    };
    if window.is_some_and(|(start, end)| start >= end) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Use a time range with Start < End",
        )
        .into());
    }
    let mut engine = AnalysisEngine::new();
    let mut activity = crate::host_bw::ActivityTimeline::default();
    if let Some((start, end)) = window {
        engine.set_completion_window(start, end);
    }
    let (mut source_start_ns, mut source_end_ns, mut source_completed_ios) = (u64::MAX, 0, 0);
    let mut selected_count = 0usize;
    let mut selected_scheduler_count = 0usize;
    let loaded=SessionReader::default().read_events(BufReader::new(File::open(path)?),|event| {
        check_cancel()?;
        if let StorageEvent::SchedulerIoWait(wait)=&event && window.is_some_and(|(start,end)|wait.ts_ns>=start&&wait.ts_ns<=end) {
            selected_scheduler_count+=1;
            if selected_scheduler_count>100_000 {return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput,"This interval contains more than 100,000 scheduler wait events. Narrow the time range; previous analysis preserved.").into());}
        }
        if let Some((start,end))=event_interval(&event) {source_start_ns=source_start_ns.min(start);source_end_ns=source_end_ns.max(end);activity.observe_range(start,end);}
        if (window.is_none() || matches!(&event,StorageEvent::BlockInsert(_)|StorageEvent::BlockIssue(_)|StorageEvent::BlockComplete(_)|StorageEvent::ObservedBlockCompletion(_)|StorageEvent::SchedulerIoWait(_))) && let Some(io)=engine.ingest(event) {
                source_completed_ios+=1;
                activity.observe(&io);
                if window.is_some_and(|(start,end)|io.completion.ts_ns>=start&&io.completion.ts_ns<=end) {
                    selected_count+=1;
                    if selected_count>100_000 {return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput,"This interval contains more than 100,000 I/O. Narrow the time range; previous analysis preserved.").into());}
                }
        }
        Ok(())
    })?;
    if window.is_some() {
        // Reset summary to the selected requests; classification/queue metrics
        // were computed from all block events and are copied without replay.
        engine = engine.select_completed(|_| true);
        let ids: std::collections::HashSet<_> = engine
            .completed_ios()
            .iter()
            .map(|io| io.issue.request_id)
            .collect();
        if !ids.is_empty() {
            let low = engine
                .completed_ios()
                .iter()
                .map(|io| io.insert.as_ref().map_or(io.issue.ts_ns, |i| i.ts_ns))
                .min()
                .unwrap()
                .saturating_sub(30_000_000_000);
            let high = engine
                .completed_ios()
                .iter()
                .map(|io| io.completion.ts_ns)
                .max()
                .unwrap()
                .saturating_add(30_000_000_000);
            let mut counts = [0usize; 5];
            SessionReader::default().visit(BufReader::new(File::open(path)?),|record| {
                check_cancel()?;
                if let WireRecord::Event {event,..}=record {
                    let near=event_interval(&event).is_some_and(|(start,end)|start<=high&&end>=low);
                    let kind=match &event {
                        StorageEvent::FileIo(_) if near=>Some(0),
                        StorageEvent::Pipeline(v) if near || v.correlation_id.is_some_and(|id|ids.contains(&id))=>Some(1),
                        StorageEvent::RequestOrigin(v) if ids.contains(&v.request_id) && near=>Some(2),
                        StorageEvent::Node(v) if v.transaction_id.is_some_and(|id|ids.contains(&id)) && near=>Some(3),
                        StorageEvent::Edge(v) if v.transaction_id.is_some_and(|id|ids.contains(&id))=>Some(4),
                        _=>None,
                    };
                    if let Some(kind)=kind {
                        counts[kind]+=1;
                        if counts[kind]>100_000 || counts[2]+counts[3]>100_000 || counts[2]+counts[4]>100_000 {
                            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput,"Evidence density exceeds the safe detail window. Narrow the interval; evidence is not silently dropped.").into());
                        }
                        engine.ingest(event);
                    }
                }
                Ok(())
            })?;
        }
    }
    // Evidence outside the detail interval must not widen its throughput span.
    if window.is_some() {
        engine = engine.select_completed(|_| true);
    }
    let after = std::fs::metadata(path)?;
    if before.len() != after.len() || before.modified()? != after.modified()? {
        return Err(std::io::Error::other(
            "Session changed during reanalysis; retry after recording stops",
        )
        .into());
    }
    let accepted_events = loaded.accepted_events;
    let latest_aggregate = if window.is_none() {
        loaded.aggregates.last().cloned()
    } else {
        None
    };
    let mut heavy_hitters = Vec::<HeavyHitterSnapshot>::new();
    if window.is_none() {
        for snapshot in &loaded.heavy_hitters {
            heavy_hitters.retain(|current| current.dimension != snapshot.dimension);
            heavy_hitters.push(snapshot.clone());
        }
    }
    let triggers = loaded.triggers.clone();
    let segments = loaded.segments.clone();
    let stack_fingerprints = loaded.stack_fingerprints.clone();
    let loss_status = loaded.health.last().map_or_else(|| "Loss counters not reported".into(), |record| match record { WireRecord::Health { kernel_drops, userspace_drops, correlation_ambiguous, correlation_expired, .. } => format!("Kernel loss: {} · userspace loss: {userspace_drops} · ambiguous: {correlation_ambiguous} · expired: {correlation_expired}", kernel_drops.map_or_else(|| "not reported".into(), |v| v.to_string())), _ => "Loss counters not reported".into() });
    let loss_status = loaded
        .source_info
        .last()
        .and_then(|r| {
            if let WireRecord::SourceInfo { status, .. } = r {
                Some(status.clone())
            } else {
                None
            }
        })
        .unwrap_or(loss_status);
    for record in &loaded.source_info {
        activity.observe_record(record);
    }
    if let Some(footer) = &loaded.footer {
        activity.observe_record(footer);
    }
    if loaded.integrity_ok != Some(true) || loaded.rejected_lines > 0 {
        activity.limitation = Some("Incomplete or rejected saved event stream".into());
    }
    Ok(LoadedAnalysis {
        activity: std::sync::Arc::new(activity),
        source_info: loaded.source_info,
        source_start_ns: if source_start_ns == u64::MAX {
            0
        } else {
            source_start_ns
        },
        source_end_ns,
        source_completed_ios,
        window_ns: window,
        load_elapsed_ms: started.elapsed().as_secs_f64() * 1000.0,
        loss_status,
        disk_stats: loaded.disk_stats,
        engine,
        accepted_events,
        rejected_lines: loaded.rejected_lines,
        integrity_ok: loaded.integrity_ok,
        graceful: loaded.graceful,
        capabilities: loaded.capabilities,
        latest_aggregate,
        heavy_hitters,
        triggers,
        segments,
        stack_fingerprints,
    })
}

pub(crate) fn event_interval(event: &StorageEvent) -> Option<(u64, u64)> {
    Some(match event {
        StorageEvent::SchedulerIoWait(v) => (v.ts_ns, v.ts_ns),
        StorageEvent::ObservedBlockCompletion(io) => (io.start_timestamp(), io.completion.ts_ns),
        StorageEvent::BlockInsert(v) => (v.ts_ns, v.ts_ns),
        StorageEvent::BlockIssue(v) => (v.ts_ns, v.ts_ns),
        StorageEvent::BlockComplete(v) => (v.ts_ns, v.ts_ns),
        StorageEvent::FileIo(v) => (v.start_ts_ns, v.end_ts_ns),
        StorageEvent::Pipeline(v) => (v.ts_ns, v.end_ts_ns.unwrap_or(v.ts_ns)),
        StorageEvent::RequestOrigin(v) => (v.ts_ns, v.ts_ns),
        StorageEvent::Node(v) => (v.start_ts_ns, v.end_or_start()),
        StorageEvent::Edge(_) => return None,
    })
}

/// Stream the selected analysis and its provenance without building a huge JSON array.
pub fn export_analysis_view(
    path: &Path,
    engine: &AnalysisEngine,
    summary: &AnalysisSummary,
    metadata: serde_json::Value,
) -> anyhow::Result<()> {
    if let Some(source) = metadata
        .get("source_session")
        .and_then(|value| value.as_str())
    {
        ensure_distinct_export(Path::new(source), path)?;
    }
    let mut writer = BufWriter::new(File::create(path)?);
    serde_json::to_writer(
        &mut writer,
        &serde_json::json!({"record":"analysis_view","version":1,"metadata":metadata,"summary":summary,"request_count":engine.completed_ios().len()}),
    )?;
    writer.write_all(b"\n")?;
    for io in engine.completed_ios() {
        let graph = engine.transaction_for(io);
        let origins = graph.file_origins_for(android_ebpf_protocol::block_request_node_id(
            io.issue.request_id,
        ));
        serde_json::to_writer(
            &mut writer,
            &serde_json::json!({"record":"completed_io_analysis","io":io,"file_candidates":origins.iter().map(|v|serde_json::json!({"file":v.file,"path":v.path,"edge_confidence":v.confidence})).collect::<Vec<_>>(),"graph":graph}),
        )?;
        writer.write_all(b"\n")?;
    }
    writer.flush()?;
    writer.get_ref().sync_all()?;
    Ok(())
}

pub fn export_csv(session_path: &Path, events_path: &Path) -> anyhow::Result<PathBuf> {
    ensure_distinct_export(session_path, events_path)?;
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
        "details_json",
    ])?;
    SessionReader::default().visit(BufReader::new(File::open(session_path)?), |record| {
        match record {
            WireRecord::DiskStats {
                elapsed_ms, raw, ..
            } => {
                let mut row = vec![String::new(); 18];
                row[0] = "disk_stats".into();
                row[1] = (elapsed_ms * 1_000_000).to_string();
                row[17] = raw;
                writer
                    .write_record(row)
                    .map_err(|e| SessionError::Io(std::io::Error::other(e)))?;
            }
            WireRecord::Event { event, .. } => {
                write_event_csv(&mut writer, &event)
                    .map_err(|e| SessionError::Io(std::io::Error::other(e)))?;
                engine.ingest(event);
            }
            _ => {}
        }
        Ok(())
    })?;
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

pub(crate) fn ensure_distinct_export(source: &Path, destination: &Path) -> anyhow::Result<()> {
    if let (Ok(source), Ok(destination)) = (source.canonicalize(), destination.canonicalize()) {
        anyhow::ensure!(
            !source
                .to_string_lossy()
                .eq_ignore_ascii_case(&destination.to_string_lossy()),
            "Choose a different export filename; the original session must be preserved"
        );
    }
    Ok(())
}

/// One row per retained request in an already filtered snapshot. File candidates
/// stay together on that row, so multi-origin membership never duplicates bytes.
pub fn export_completed_io_csv(path: &Path, engine: &AnalysisEngine) -> anyhow::Result<()> {
    let mut writer = csv::Writer::from_path(path)?;
    writer.write_record([
        "request_id",
        "device",
        "issue_ns",
        "completion_ns",
        "sector_512b",
        "end_sector_exclusive",
        "extent_bytes",
        "rw_payload_bytes",
        "operation",
        "issuer_pid",
        "issuer_tid",
        "issuer_comm",
        "queue_latency_ns",
        "device_latency_ns",
        "total_latency_ns",
        "access_pattern",
        "issue_depth_observed",
        "d2d_ns",
        "c2c_ns",
        "file_candidates_json",
        "completed_io_json",
        "rolling_c2c_payload_bytes",
        "rolling_c2c_duration_ns",
        "rolling_c2c_mib_s",
        "rolling_d2d_payload_bytes",
        "rolling_d2d_duration_ns",
        "rolling_d2d_mib_s",
        "issue_cpu",
        "completion_cpu",
    ])?;
    for io in engine.completed_ios() {
        let graph = engine.transaction_for(io);
        let origins = graph.file_origins_for(android_ebpf_protocol::block_request_node_id(
            io.issue.request_id,
        ));
        let payload = if matches!(io.issue.operation, IoOperation::Read | IoOperation::Write) {
            io.issue.bytes
        } else {
            0
        };
        writer.write_record([
            io.issue.request_id.to_string(), format!("{}:{}",io.issue.device_major,io.issue.device_minor),
            io.issue_timestamp().map(|v|v.to_string()).unwrap_or_default(), io.completion.ts_ns.to_string(),
            io.issue.sector.to_string(), io.issue.sector.saturating_add(io.issue.sectors as u64).to_string(),
            io.issue.bytes.to_string(), payload.to_string(), format!("{:?}",io.issue.operation),
            io.issuer_pid().map(|v|v.to_string()).unwrap_or_default(), io.issuer_tid().map(|v|v.to_string()).unwrap_or_default(), io.issue.comm.clone(),
            io.queue_latency_ns.map(|v|v.to_string()).unwrap_or_default(), io.device_latency_ns.map(|v|v.to_string()).unwrap_or_default(), io.total_latency_ns.map(|v|v.to_string()).unwrap_or_default(), format!("{:?}",io.access_pattern),
            io.detail_timing.issue_depth.map(|v|v.to_string()).unwrap_or_default(), io.detail_timing.issue_gap_ns.map(|v|v.to_string()).unwrap_or_default(), io.detail_timing.completion_gap_ns.map(|v|v.to_string()).unwrap_or_default(),
            serde_json::to_string(&origins.iter().map(|v|serde_json::json!({"file":v.file,"path":v.path,"edge_confidence":v.confidence})).collect::<Vec<_>>())?, serde_json::to_string(io)?,
            io.detail_timing.completion_bandwidth.as_ref().map(|r|r.payload_bytes.to_string()).unwrap_or_default(),
            io.detail_timing.completion_bandwidth.as_ref().map(|r|r.duration_ns.to_string()).unwrap_or_default(),
            io.detail_timing.completion_bandwidth.as_ref().and_then(|r|r.mib_s()).map(|v|v.to_string()).unwrap_or_default(),
            io.detail_timing.issue_bandwidth.as_ref().map(|r|r.payload_bytes.to_string()).unwrap_or_default(),
            io.detail_timing.issue_bandwidth.as_ref().map(|r|r.duration_ns.to_string()).unwrap_or_default(),
            io.detail_timing.issue_bandwidth.as_ref().and_then(|r|r.mib_s()).map(|v|v.to_string()).unwrap_or_default(),
            io.issuer_cpu().map(|v|v.to_string()).unwrap_or_default(),
            io.completion.cpu.map(|v|v.to_string()).unwrap_or_default(),
        ])?;
    }
    writer.flush()?;
    Ok(())
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
        (
            "busy_ns",
            summary.busy_ns.map(|n| n.to_string()).unwrap_or_default(),
        ),
        (
            "idle_ns",
            summary.idle_ns.map(|n| n.to_string()).unwrap_or_default(),
        ),
        ("file_ios", summary.file_ios.to_string()),
        (
            "attributed_file_ios",
            summary.attributed_file_ios.to_string(),
        ),
        (
            "block_attribution_exact",
            summary.attribution.exact.to_string(),
        ),
        (
            "block_attribution_probable",
            summary.attribution.probable.to_string(),
        ),
        (
            "block_attribution_probable_async",
            summary.attribution.probable_async.to_string(),
        ),
        (
            "block_attribution_unattributed",
            summary.attribution.unattributed.to_string(),
        ),
        (
            "block_attribution_multi_origin",
            summary.attribution.multi_origin.to_string(),
        ),
        (
            "max_queue_depth",
            summary
                .max_queue_depth
                .map(|n| n.to_string())
                .unwrap_or_default(),
        ),
        (
            "p50_latency_ns",
            summary
                .p50_latency_ns
                .map(|n| n.to_string())
                .unwrap_or_default(),
        ),
        (
            "p95_latency_ns",
            summary
                .p95_latency_ns
                .map(|n| n.to_string())
                .unwrap_or_default(),
        ),
        (
            "p99_latency_ns",
            summary
                .p99_latency_ns
                .map(|n| n.to_string())
                .unwrap_or_default(),
        ),
    ] {
        writer.write_record([metric, &value])?;
    }
    writer.flush()?;
    Ok(())
}

fn write_event_csv(writer: &mut csv::Writer<File>, event: &StorageEvent) -> anyhow::Result<()> {
    match event {
        StorageEvent::SchedulerIoWait(wait) => {
            let mut row: [String; 18] = std::array::from_fn(|_| String::new());
            row[0] = "scheduler_iowait".into();
            row[1] = wait.ts_ns.to_string();
            row[8] = wait.pid.map(|pid| pid.to_string()).unwrap_or_default();
            row[9] = wait.tid.to_string();
            row[10] = wait.comm.clone();
            row[17] = serde_json::to_string(wait)?;
            writer.write_record(row)?;
        }
        StorageEvent::ObservedBlockCompletion(io) => writer.write_record([
            "observed_block_completion".into(),
            io.completion.ts_ns.to_string(),
            io.issue_timestamp()
                .map(|n| n.to_string())
                .unwrap_or_default(),
            io.issue.request_id.to_string(),
            format!("{}:{}", io.issue.device_major, io.issue.device_minor),
            io.issue.sector.to_string(),
            io.issue.bytes.to_string(),
            format!("{:?}", io.issue.operation).to_lowercase(),
            io.issuer_pid().map(|n| n.to_string()).unwrap_or_default(),
            io.issuer_tid().map(|n| n.to_string()).unwrap_or_default(),
            io.issue.comm.clone(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            serde_json::to_string(io)?,
        ])?,
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
            serde_json::to_string(issue)?,
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
            serde_json::to_string(insert)?,
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
            serde_json::to_string(complete)?,
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
            serde_json::to_string(file)?,
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
            serde_json::to_string(stage)?,
        ])?,
        StorageEvent::RequestOrigin(origin) => writer.write_record([
            "request_origin".to_owned(),
            origin.ts_ns.to_string(),
            String::new(),
            origin.request_id.to_string(),
            format!(
                "{}:{}:{}",
                origin.file.fs_device_major, origin.file.fs_device_minor, origin.file.inode
            ),
            String::new(),
            origin
                .bytes
                .map(|value| value.to_string())
                .unwrap_or_default(),
            format!("{:?}", origin.operation).to_lowercase(),
            origin.pid.to_string(),
            origin.tid.to_string(),
            format!("{:?}", origin.origin).to_lowercase(),
            String::new(),
            origin
                .path
                .as_ref()
                .and_then(|snapshot| snapshot.path.clone())
                .unwrap_or_default(),
            format!(
                "file={:?};request={:?}{}",
                origin.file_origin_confidence,
                origin.request_lifetime_confidence,
                if origin.incomplete { ";incomplete" } else { "" }
            )
            .to_lowercase(),
            String::new(),
            String::new(),
            String::new(),
            serde_json::to_string(origin)?,
        ])?,
        StorageEvent::Node(node) => writer.write_record([
            format!("node_{:?}", node.kind).to_lowercase(),
            node.end_or_start().to_string(),
            node.start_ts_ns.to_string(),
            node.node_id.to_string(),
            node.file
                .as_ref()
                .map(|file| {
                    format!(
                        "{}:{}:{}",
                        file.fs_device_major, file.fs_device_minor, file.inode
                    )
                })
                .unwrap_or_default(),
            String::new(),
            node.bytes
                .map(|value| value.to_string())
                .unwrap_or_default(),
            node.operation
                .map(|value| format!("{value:?}").to_lowercase())
                .unwrap_or_default(),
            node.pid.to_string(),
            node.tid.to_string(),
            node.name.clone(),
            String::new(),
            node.path
                .as_ref()
                .and_then(|value| value.path.clone())
                .unwrap_or_default(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            serde_json::to_string(node)?,
        ])?,
        StorageEvent::Edge(edge) => writer.write_record([
            "edge".to_owned(),
            String::new(),
            String::new(),
            edge.edge_id.to_string(),
            format!("{}->{}", edge.from_node_id, edge.to_node_id),
            String::new(),
            String::new(),
            format!("{:?}", edge.relation).to_lowercase(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            format!("{:?}", edge.confidence).to_lowercase(),
            String::new(),
            String::new(),
            String::new(),
            serde_json::to_string(edge)?,
        ])?,
    }
    Ok(())
}
