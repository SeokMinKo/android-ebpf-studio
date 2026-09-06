use std::{
    io::{BufRead, BufReader, Read, Write},
    path::PathBuf,
    process::{Child, ChildStdin},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

use android_ebpf_protocol::{CaptureControlCommand, DiagnosticLevel, DiagnosticRecord, WireRecord};
use crossbeam_channel::Sender;

use crate::adb::{AdbClient, AdbDevice, PreflightReport};
use crate::diagnostics::{RotatingJsonl, host_record, parse_agent_diagnostic};
use crate::session::LoadedAnalysis;

fn bounded_lines(input: impl Read, limit: usize) -> impl Iterator<Item = std::io::Result<String>> {
    let mut reader = BufReader::new(input);
    std::iter::from_fn(move || {
        let mut bytes = Vec::new();
        match (&mut reader)
            .take(limit as u64 + 1)
            .read_until(b'\n', &mut bytes)
        {
            Ok(0) => None,
            Err(error) => Some(Err(error)),
            Ok(_) if bytes.len() > limit => {
                if bytes.last() != Some(&b'\n') {
                    loop {
                        let buffer = match reader.fill_buf() {
                            Ok(v) => v,
                            Err(error) => return Some(Err(error)),
                        };
                        if buffer.is_empty() {
                            break;
                        }
                        let newline = buffer.iter().position(|b| *b == b'\n');
                        let consumed = newline.map_or(buffer.len(), |p| p + 1);
                        reader.consume(consumed);
                        if newline.is_some() {
                            break;
                        }
                    }
                }
                Some(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "collector line exceeded bounded buffer; raw tail rejected",
                )))
            }
            Ok(_) => {
                while matches!(bytes.last(), Some(b'\n' | b'\r')) {
                    bytes.pop();
                }
                Some(
                    String::from_utf8(bytes)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
                )
            }
        }
    })
}

#[cfg(test)]
mod stream_tests {
    #[test]
    fn oversized_line_does_not_turn_its_tail_into_an_event() {
        let input = b"good\n0123456789fake-event\nlast\n";
        let mut lines = super::bounded_lines(&input[..], 8);
        assert_eq!(lines.next().unwrap().unwrap(), "good");
        assert!(lines.next().unwrap().is_err());
        assert_eq!(lines.next().unwrap().unwrap(), "last");
        assert!(lines.next().is_none());
    }
}

#[derive(Debug)]
pub enum HostMessage {
    Devices(Result<Vec<AdbDevice>, String>),
    Preflight(Result<PreflightReport, String>),
    Status(String),
    AnalysisStarted,
    Record(WireRecord),
    Diagnostic(DiagnosticRecord),
    SessionLoaded(PathBuf, Result<Box<LoadedAnalysis>, String>),
    ViewExported(Result<PathBuf, String>),
    RawTraceExported(Result<PathBuf, String>),
    Exported(Result<PathBuf, String>),
    Ended(Result<(), String>),
    Finalized(Result<Option<android_ebpf_protocol::FilePathCoverage>, String>),
}

#[derive(Debug, Clone)]
pub struct CaptureHandle {
    stop: Arc<AtomicBool>,
    child: Arc<Mutex<Option<Child>>>,
    control: Arc<Mutex<Option<ChildStdin>>>,
}

impl CaptureHandle {
    pub fn stop(&self) {
        if self.stop.swap(true, Ordering::AcqRel) {
            return;
        }
        // Closing stdin asks the collector to stop. Keep stdout open to drain it.
        if let Ok(mut guard) = self.control.lock() {
            guard.take();
        }
        let child = self.child.clone();
        thread::spawn(move || {
            for _ in 0..100 {
                thread::sleep(std::time::Duration::from_millis(100));
                if let Ok(mut guard) = child.lock()
                    && guard
                        .as_mut()
                        .is_none_or(|p| p.try_wait().ok().flatten().is_some())
                {
                    return;
                }
            }
            if let Ok(mut guard) = child.lock()
                && let Some(child) = guard.as_mut()
            {
                let _ = child.kill();
            }
        });
    }

    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        self.stop.clone()
    }

    pub fn send_control(&self, command: &CaptureControlCommand) -> Result<(), String> {
        let mut guard = self
            .control
            .lock()
            .map_err(|_| "capture control lock is poisoned".to_owned())?;
        let input = guard
            .as_mut()
            .ok_or_else(|| "capture control channel is unavailable".to_owned())?;
        serde_json::to_writer(&mut *input, command)
            .map_err(|error| format!("capture control encode failed: {error}"))?;
        input
            .write_all(b"\n")
            .and_then(|_| input.flush())
            .map_err(|error| format!("capture control write failed: {error}"))
    }
}

pub fn refresh_devices(client: AdbClient, tx: Sender<HostMessage>) {
    thread::spawn(move || {
        let result = client.list_devices().map_err(|error| error.to_string());
        let _ = tx.send(HostMessage::Devices(result));
    });
}

pub fn run_preflight(client: AdbClient, serial: String, tx: Sender<HostMessage>) {
    thread::spawn(move || {
        let _ = tx.send(HostMessage::Status("Running device preflight…".into()));
        let result = client.preflight(&serial).map_err(|error| error.to_string());
        let _ = tx.send(HostMessage::Preflight(result));
    });
}

#[allow(clippy::too_many_arguments)]
pub fn start_adb(
    client: AdbClient,
    serial: String,
    local_agent: PathBuf,
    local_bpf: PathBuf,
    session_id: String,
    agent_log: PathBuf,
    log_level: String,
    tx: Sender<HostMessage>,
) -> CaptureHandle {
    let stop = Arc::new(AtomicBool::new(false));
    let child_slot = Arc::new(Mutex::new(None));
    let control_slot = Arc::new(Mutex::new(None));
    let handle = CaptureHandle {
        stop: stop.clone(),
        child: child_slot.clone(),
        control: control_slot.clone(),
    };
    thread::spawn(move || {
        let log_host = |record: DiagnosticRecord| {
            let _ = tx.send(HostMessage::Diagnostic(record));
        };
        log_host(host_record(
            &session_id,
            DiagnosticLevel::Info,
            "capture.lifecycle",
            "CAPTURE_DEPLOYING",
            "started",
            None,
        ));
        let mut detected = None;
        let mut capture_ready = false;
        let mut measurement_seen = false;
        let result = (|| -> Result<(), String> {
            tx.send(HostMessage::Status(
                "Preparing: detecting root, kernel and file mapping capabilities…".into(),
            ))
            .ok();
            let report = client
                .preflight(&serial)
                .map_err(|error| error.to_string())?;
            let profile_path = agent_log.with_file_name("device-profile.json");
            std::fs::write(
                &profile_path,
                serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            let ready = report.full_ebpf_ready();
            let fallback_report = report.clone();
            detected = Some(report.clone());
            tx.send(HostMessage::Preflight(Ok(report))).ok();
            if !ready {
                if fallback_report.perfetto {
                    return capture_perfetto(&client, &fallback_report, &stop, &tx, &agent_log);
                }
                return capture_diskstats(&client, &fallback_report, &stop, &tx);
            }
            if stop.load(Ordering::Acquire) {
                return Ok(());
            }
            tx.send(HostMessage::Status("Deploying Android collector…".into()))
                .ok();
            client
                .deploy(&serial, &local_agent, &local_bpf)
                .map_err(|error| error.to_string())?;
            if stop.load(Ordering::Acquire) {
                return Ok(());
            }
            let mut child = client
                .start_capture(&serial, &session_id, &log_level)
                .map_err(|error| error.to_string())?;
            let stdout = child
                .stdout
                .take()
                .ok_or("collector stdout is unavailable")?;
            let stderr = child
                .stderr
                .take()
                .ok_or("collector stderr is unavailable")?;
            let stdin = child
                .stdin
                .take()
                .ok_or("collector control stdin is unavailable")?;
            *control_slot
                .lock()
                .map_err(|_| "capture control lock is poisoned")? = Some(stdin);
            *child_slot.lock().map_err(|_| "capture lock is poisoned")? = Some(child);
            let readiness = Arc::new(AtomicBool::new(false));
            let ready_signal = readiness.clone();
            let watched_child = child_slot.clone();
            thread::spawn(move || {
                for _ in 0..300 {
                    if ready_signal.load(Ordering::Acquire) {
                        return;
                    }
                    if let Ok(mut slot) = watched_child.lock()
                        && slot
                            .as_mut()
                            .is_none_or(|child| child.try_wait().ok().flatten().is_some())
                    {
                        return;
                    }
                    thread::sleep(std::time::Duration::from_millis(100));
                }
                if !ready_signal.load(Ordering::Acquire)
                    && let Ok(mut slot) = watched_child.lock()
                    && let Some(child) = slot.as_mut()
                {
                    let _ = child.kill();
                }
            });
            if stop.load(Ordering::Acquire)
                && let Ok(mut guard) = control_slot.lock()
            {
                guard.take();
            }
            tx.send(HostMessage::Status(
                "Waiting for collector readiness…".into(),
            ))
            .ok();

            let error_tx = tx.clone();
            let error_session = session_id.clone();
            let error_log = agent_log.clone();
            let stderr_thread = thread::spawn(move || {
                read_stderr_lines(stderr, &error_log, &error_session, error_tx)
            });
            for line in bounded_lines(stdout, 1024 * 1024) {
                match line {
                    Ok(line) if line.len() <= 1024 * 1024 => {
                        match serde_json::from_str::<WireRecord>(&line) {
                            Ok(record) => {
                                measurement_seen |= match &record {
                                    WireRecord::Hello { .. } | WireRecord::Control { .. } => false,
                                    WireRecord::Health { emitted_events, .. } => {
                                        *emitted_events > 0
                                    }
                                    WireRecord::Footer { events_seen, .. } => *events_seen > 0,
                                    _ => true,
                                };
                                if matches!(&record, WireRecord::Capabilities { .. }) {
                                    capture_ready = true;
                                    readiness.store(true, Ordering::Release);
                                    tx.send(HostMessage::Status(
                                        "Capturing eBPF storage events".into(),
                                    ))
                                    .ok();
                                }
                                if tx.send(HostMessage::Record(record)).is_err() {
                                    break;
                                }
                            }
                            Err(error) => {
                                log_host(host_record(
                                    &session_id,
                                    DiagnosticLevel::Warn,
                                    "measurement.decode",
                                    "EVENT_DECODE_REJECTED",
                                    "rejected",
                                    Some(error.to_string()),
                                ));
                            }
                        }
                    }
                    Ok(_) => {
                        log_host(host_record(
                            &session_id,
                            DiagnosticLevel::Warn,
                            "measurement.decode",
                            "EVENT_LINE_TOO_LARGE",
                            "rejected",
                            Some("collector line larger than 1 MiB".into()),
                        ));
                    }
                    Err(error) => return Err(format!("collector stream failed: {error}")),
                };
            }
            let mut exit_error = None;
            loop {
                let status = child_slot
                    .lock()
                    .map_err(|_| "capture lock poisoned")?
                    .as_mut()
                    .ok_or("collector missing")?
                    .try_wait()
                    .map_err(|e| e.to_string())?;
                if let Some(status) = status {
                    if !status.success() {
                        exit_error = Some(format!(
                            "collector exited with status {status}; partial data preserved"
                        ));
                    }
                    break;
                }
                thread::sleep(std::time::Duration::from_millis(20));
            }
            stderr_thread
                .join()
                .map_err(|_| "collector diagnostic reader panicked".to_owned())?;
            if let Some(error) = exit_error {
                return Err(error);
            }
            if !capture_ready && !stop.load(Ordering::Acquire) {
                return Err(
                    "collector ended before reporting readiness; partial data preserved".into(),
                );
            }
            if let Ok(mut guard) = control_slot.lock() {
                guard.take();
            }
            Ok(())
        })();
        if result.is_err() {
            if let Ok(mut control) = control_slot.lock() {
                control.take();
            }
            if let Ok(mut slot) = child_slot.lock()
                && let Some(child) = slot.as_mut()
            {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        let result = match result {
            Err(error)
                if !capture_ready
                    && !measurement_seen
                    && !stop.load(Ordering::Acquire)
                    && detected.as_ref().is_some_and(|r| r.full_ebpf_ready()) =>
            {
                log_host(host_record(
                    &session_id,
                    DiagnosticLevel::Warn,
                    "capture.fallback",
                    "EBPF_UNAVAILABLE",
                    "degraded",
                    Some(error.clone()),
                ));
                (|| -> Result<(), String> {
                    // Revalidate the original target after the failed collector
                    // exits. Never continue across a reboot in the same session.
                    let original = detected.as_ref().unwrap();
                    let mut report = client.preflight(&serial).map_err(|e| e.to_string())?;
                    if original.boot_id.is_empty() || original.boot_id != report.boot_id {
                        return Err("Device boot changed during preparation; partial data preserved. Start a new session after reconnecting".into());
                    }
                    report.ebpf_start_error = Some(error);
                    report.diagnostics.push("eBPF collector startup failed; automatic fallback uses Perfetto when available, otherwise accessible device counters".into());
                    std::fs::write(
                        agent_log.with_file_name("device-profile-before-fallback.json"),
                        serde_json::to_vec_pretty(original).map_err(|e| e.to_string())?,
                    )
                    .map_err(|e| e.to_string())?;
                    std::fs::write(
                        agent_log.with_file_name("device-profile.json"),
                        serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?,
                    )
                    .map_err(|e| e.to_string())?;
                    tx.send(HostMessage::Preflight(Ok(report.clone()))).ok();
                    tx.send(HostMessage::Record(WireRecord::SourceInfo {
                        schema_version: android_ebpf_protocol::SCHEMA_VERSION,
                        source: "ebpf".into(),
                        status: "eBPF startup failed; automatic fallback selected · see Diagnostics for the original error".into(),
                        metadata: serde_json::json!({"stage":"fallback", "error":report.ebpf_start_error.as_deref(),
                            "next_source":if report.perfetto {"perfetto"} else {"device_counters"}}),
                    })).ok();
                    if stop.load(Ordering::Acquire) {
                        return Ok(());
                    }
                    if report.perfetto {
                        capture_perfetto(&client, &report, &stop, &tx, &agent_log)
                    } else {
                        capture_diskstats(&client, &report, &stop, &tx)
                    }
                })()
            }
            value => value,
        };
        match &result {
            Ok(()) => log_host(host_record(
                &session_id,
                DiagnosticLevel::Info,
                "capture.lifecycle",
                "CAPTURE_ENDED",
                "success",
                None,
            )),
            Err(error) => log_host(host_record(
                &session_id,
                DiagnosticLevel::Error,
                "capture.lifecycle",
                "CAPTURE_ABNORMAL_EXIT",
                "failed",
                Some(error.clone()),
            )),
        }
        let _ = tx.send(HostMessage::Ended(result));
    });
    handle
}

fn read_stderr_lines(
    stderr: impl std::io::Read,
    log_path: &std::path::Path,
    session_id: &str,
    tx: Sender<HostMessage>,
) {
    let mut writer = match RotatingJsonl::create(log_path) {
        Ok(writer) => Some(writer),
        Err(error) => {
            let _ = tx.send(HostMessage::Diagnostic(host_record(
                session_id,
                DiagnosticLevel::Error,
                "agent.diagnostic.write",
                "LOG_WRITE_FAILED",
                "failed",
                Some(error.to_string()),
            )));
            None
        }
    };
    for line in bounded_lines(stderr, 64 * 1024) {
        let record = match line {
            Ok(line) if line.len() <= 64 * 1024 => parse_agent_diagnostic(&line, session_id),
            Ok(_) => host_record(
                session_id,
                DiagnosticLevel::Warn,
                "agent.diagnostic.decode",
                "AGENT_DIAGNOSTIC_TOO_LARGE",
                "rejected",
                None,
            ),
            Err(error) => host_record(
                session_id,
                DiagnosticLevel::Error,
                "agent.diagnostic.read",
                "AGENT_DIAGNOSTIC_READ_FAILED",
                "failed",
                Some(error.to_string()),
            ),
        };
        let write_error = writer
            .as_mut()
            .and_then(|log_writer| log_writer.append(&record).err());
        if let Some(error) = write_error {
            let _ = tx.send(HostMessage::Diagnostic(host_record(
                session_id,
                DiagnosticLevel::Error,
                "agent.diagnostic.write",
                "LOG_WRITE_FAILED",
                "failed",
                Some(error.to_string()),
            )));
            writer = None;
        }
        if tx.send(HostMessage::Diagnostic(record)).is_err() {
            break;
        }
    }
}

fn capture_diskstats(
    client: &AdbClient,
    report: &PreflightReport,
    stop: &AtomicBool,
    tx: &Sender<HostMessage>,
) -> Result<(), String> {
    tx.send(HostMessage::Status(
        "Recording device counters · FilePath and individual I/O latency unavailable".into(),
    ))
    .ok();
    let started = std::time::Instant::now();
    loop {
        let (boot_id, raw) = client
            .disk_stats(&report.serial, report.root_method)
            .map_err(|e| e.to_string())?;
        if boot_id != report.boot_id {
            return Err("Phone rebooted during capture; device counters preserved. Retry Start to create a new session.".into());
        }
        tx.send(HostMessage::Record(WireRecord::DiskStats {
            schema_version: android_ebpf_protocol::SCHEMA_VERSION,
            elapsed_ms: started.elapsed().as_millis() as u64,
            boot_id,
            raw,
        }))
        .map_err(|e| e.to_string())?;
        if stop.load(Ordering::Acquire) {
            break;
        }
        for _ in 0..10 {
            if stop.load(Ordering::Acquire) {
                break;
            }
            thread::sleep(std::time::Duration::from_millis(100));
        }
    }
    tx.send(HostMessage::Record(WireRecord::Footer {
        schema_version: android_ebpf_protocol::SCHEMA_VERSION,
        events_seen: 0,
        events_persisted: 0,
        events_dropped: 0,
        events_rejected: 0,
        graceful: Some(true),
    }))
    .ok();
    Ok(())
}

fn capture_perfetto(
    client: &AdbClient,
    report: &PreflightReport,
    stop: &AtomicBool,
    tx: &Sender<HostMessage>,
    agent_log: &std::path::Path,
) -> Result<(), String> {
    use crate::perfetto_capture::PerfettoCapture;
    use android_ebpf_protocol::SCHEMA_VERSION;
    if stop.load(Ordering::Acquire) {
        return Ok(());
    }
    let directory = agent_log.with_file_name("perfetto");
    let capture = match PerfettoCapture::start(
        client.clone(),
        &report.serial,
        &directory,
        3_600_000,
    ) {
        Ok(capture) => capture,
        Err(error) => {
            let detail = error.to_string();
            if let Ok(mut failure) = error.downcast::<crate::perfetto_capture::StartupFailure>() {
                tx.send(HostMessage::Status(
                    "Perfetto startup failed; stopping the owned capture and recovering its data…"
                        .into(),
                ))
                .ok();
                match failure.capture.finish_failed_start() {
                    Ok(Some(decoded)) => {
                        tx.send(HostMessage::AnalysisStarted).ok();
                        crate::perfetto_session::project_records(
                            &decoded,
                            "perfetto/capture.pftrace",
                            |mut record| {
                                if let WireRecord::SourceInfo {
                                    status, metadata, ..
                                } = &mut record
                                {
                                    *status = format!(
                                        "Recovered partial capture after startup failure · {status}"
                                    );
                                    metadata["startup_error"] = detail.clone().into();
                                    std::fs::write(
                                        directory.join("analysis-quality.json"),
                                        serde_json::to_vec_pretty(metadata)?,
                                    )?;
                                }
                                tx.send(HostMessage::Record(record))
                                    .map_err(|e| anyhow::anyhow!(e.to_string()))
                            },
                        )
                        .map_err(|e| {
                            format!(
                                "{detail}; recovered raw trace retained but analysis failed: {e}"
                            )
                        })?;
                        return Err(format!(
                            "{detail}. Partial I/O recovered; no replacement collector started. Start again to retry; raw trace and recovery manifest preserved at {}",
                            directory.display()
                        ));
                    }
                    Ok(None) => {} // No owned process or accessible trace remains.
                    Err(cleanup) => {
                        return Err(format!(
                            "{detail}. Recovery could not finish: {cleanup}. No replacement collector was started. Reconnect the original phone and use Recover from original phone; finite capture and manifest retained at {}",
                            directory.display()
                        ));
                    }
                }
            }
            tx.send(HostMessage::Diagnostic(host_record(
                "perfetto",
                DiagnosticLevel::Warn,
                "capture.fallback",
                "PERFETTO_UNAVAILABLE",
                "degraded",
                Some(format!(
                    "{detail}; no running capture to replace; trying accessible device counters"
                )),
            )))
            .ok();
            return capture_diskstats(client, report, stop, tx);
        }
    };
    tx.send(HostMessage::Record(WireRecord::Hello {
        schema_version: SCHEMA_VERSION,
        agent_version: format!("host-perfetto / {}", report.perfetto_version),
        boot_id: report.boot_id.clone(),
        kernel_release: report.kernel_release.clone(),
    }))
    .ok();
    tx.send(HostMessage::Record(WireRecord::SourceInfo{schema_version:SCHEMA_VERSION,source:"perfetto".into(),status:"Perfetto recording · individual I/O and loss statistics available after Stop".into(),metadata:serde_json::json!({"stage":"recording","block_activity_scope":"unfiltered_issue_complete_v1","raw_trace":"perfetto/capture.pftrace","recovery_manifest":"perfetto/perfetto-owner.json","duration_limit_ms":3_600_000,"file_limit_bytes":268_435_456,"file_path":"Unresolved: block tracepoints do not provide file/inode mapping"})})).ok();
    let started = std::time::Instant::now();
    let mut counters_failed = false;
    while !stop.load(Ordering::Acquire) {
        if !capture.owned_process_alive().map_err(|e| {
            format!(
                "{e}. Perfetto trace and recovery manifest preserved at {}",
                directory.display()
            )
        })? {
            break;
        }
        if let Ok((boot_id, raw)) = client.disk_stats(&report.serial, crate::adb::RootMethod::Shell)
        {
            tx.send(HostMessage::Record(WireRecord::DiskStats {
                schema_version: SCHEMA_VERSION,
                elapsed_ms: started.elapsed().as_millis() as u64,
                boot_id,
                raw,
            }))
            .ok();
        } else if !counters_failed {
            counters_failed = true;
            tx.send(HostMessage::Status("Perfetto recording · live device counters unavailable; individual I/O analyzed after Stop".into())).ok();
        }
        let bytes = client
            .unprivileged_text(
                &report.serial,
                &["stat", "-c", "%s", &capture.owner.remote_trace],
            )
            .ok()
            .and_then(|v| v.parse::<u64>().ok());
        tx.send(HostMessage::Status(format!("Perfetto recording · {} s · trace {} · Stop to analyze · automatic limit 60 min / 256 MiB",started.elapsed().as_secs(),bytes.map_or("size unavailable".into(),|n|format!("{:.1} KiB",n as f64/1024.0))))).ok();
        for _ in 0..10 {
            if stop.load(Ordering::Acquire) {
                break;
            }
            thread::sleep(std::time::Duration::from_millis(100));
        }
    }
    tx.send(HostMessage::Status(
        "Stopping Perfetto: waiting for process exit and retrieving raw trace…".into(),
    ))
    .ok();
    let decoded = capture
        .stop_and_pull()
        .map_err(|e| format!("{e}. Raw data/recovery manifest: {}", directory.display()))?;
    tx.send(HostMessage::AnalysisStarted).ok();
    crate::perfetto_session::project_records(&decoded, "perfetto/capture.pftrace", |record| {
        if let WireRecord::SourceInfo { metadata, .. } = &record {
            std::fs::write(
                directory.join("analysis-quality.json"),
                serde_json::to_vec_pretty(metadata)?,
            )?;
        }
        tx.send(HostMessage::Record(record))
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        Ok(())
    })
    .map_err(|e| e.to_string())?;
    Ok(())
}
