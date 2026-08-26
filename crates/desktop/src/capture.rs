use std::{
    io::{BufRead, BufReader, Read},
    path::PathBuf,
    process::Child,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

use android_ebpf_protocol::WireRecord;
use crossbeam_channel::Sender;

use crate::adb::{AdbClient, AdbDevice, PreflightReport};

#[derive(Debug)]
pub enum HostMessage {
    Devices(Result<Vec<AdbDevice>, String>),
    Preflight(Result<PreflightReport, String>),
    Status(String),
    Record(WireRecord),
    Diagnostic(String),
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
    tx: Sender<HostMessage>,
) -> CaptureHandle {
    let stop = Arc::new(AtomicBool::new(false));
    let child_slot = Arc::new(Mutex::new(None));
    let handle = CaptureHandle {
        stop: stop.clone(),
        child: child_slot.clone(),
    };
    thread::spawn(move || {
        let result = (|| -> Result<(), String> {
            tx.send(HostMessage::Status("Deploying Android collector…".into()))
                .ok();
            client
                .deploy(&serial, &local_agent, &local_bpf)
                .map_err(|error| error.to_string())?;
            let mut child = client
                .start_capture(&serial)
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
            thread::spawn(move || read_bounded_stderr(stderr, error_tx));
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
                                tx.send(HostMessage::Diagnostic(format!(
                                    "Rejected collector record: {error}"
                                )))
                                .ok();
                            }
                        }
                    }
                    Ok(_) => {
                        tx.send(HostMessage::Diagnostic(
                            "Rejected collector line larger than 1 MiB".into(),
                        ))
                        .ok();
                    }
                    Err(error) => return Err(format!("collector stream failed: {error}")),
                };
            }
            if let Ok(mut guard) = child_slot.lock()
                && let Some(child) = guard.as_mut()
            {
                let _ = child.wait();
            }
            Ok(())
        })();
        let _ = tx.send(HostMessage::Ended(result));
    });
    handle
}

fn read_bounded_stderr(mut stderr: impl Read, tx: Sender<HostMessage>) {
    let mut buffer = vec![0_u8; 16 * 1024];
    if let Ok(read) = stderr.read(&mut buffer)
        && read > 0
    {
        let diagnostic = String::from_utf8_lossy(&buffer[..read]).trim().to_owned();
        if !diagnostic.is_empty() {
            let _ = tx.send(HostMessage::Diagnostic(diagnostic));
        }
    }
}
