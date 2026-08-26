use std::{
    io::{BufRead, BufReader},
    path::PathBuf,
    process::Child,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

use android_ebpf_protocol::{DiagnosticLevel, DiagnosticRecord, WireRecord};
use crossbeam_channel::Sender;

use crate::adb::{AdbClient, AdbDevice, PreflightReport};
use crate::diagnostics::{RotatingJsonl, host_record, parse_agent_diagnostic};

#[derive(Debug)]
pub enum HostMessage {
    Devices(Result<Vec<AdbDevice>, String>),
    Preflight(Result<PreflightReport, String>),
    Status(String),
    Record(WireRecord),
    Diagnostic(DiagnosticRecord),
    Ended(Result<(), String>),
}

#[derive(Debug, Clone)]
pub struct CaptureHandle {
    stop: Arc<AtomicBool>,
    child: Arc<Mutex<Option<Child>>>,
}

impl CaptureHandle {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Release);
        if let Ok(mut guard) = self.child.lock()
            && let Some(child) = guard.as_mut()
        {
            let _ = child.kill();
        }
    }

    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        self.stop.clone()
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
    let handle = CaptureHandle {
        stop: stop.clone(),
        child: child_slot.clone(),
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
        let result = (|| -> Result<(), String> {
            tx.send(HostMessage::Status("Deploying Android collector…".into()))
                .ok();
            client
                .deploy(&serial, &local_agent, &local_bpf)
                .map_err(|error| error.to_string())?;
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
            *child_slot.lock().map_err(|_| "capture lock is poisoned")? = Some(child);
            tx.send(HostMessage::Status("Capturing eBPF storage events".into()))
                .ok();

            let error_tx = tx.clone();
            let error_session = session_id.clone();
            let stderr_thread = thread::spawn(move || {
                read_stderr_lines(stderr, &agent_log, &error_session, error_tx)
            });
            for line in BufReader::new(stdout).lines() {
                if stop.load(Ordering::Acquire) {
                    break;
                }
                match line {
                    Ok(line) if line.len() <= 1024 * 1024 => {
                        match serde_json::from_str::<WireRecord>(&line) {
                            Ok(record) => {
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
            if let Ok(mut guard) = child_slot.lock()
                && let Some(child) = guard.as_mut()
            {
                let status = child
                    .wait()
                    .map_err(|error| format!("collector wait failed: {error}"))?;
                if !status.success() && !stop.load(Ordering::Acquire) {
                    exit_error = Some(format!("collector exited with status {status}"));
                }
            }
            stderr_thread
                .join()
                .map_err(|_| "collector diagnostic reader panicked".to_owned())?;
            if let Some(error) = exit_error {
                return Err(error);
            }
            Ok(())
        })();
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
    for line in BufReader::new(stderr).lines() {
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
