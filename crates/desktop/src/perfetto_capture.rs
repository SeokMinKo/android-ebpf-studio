//! Non-root Perfetto transport. Each capture owns one finite session, process
//! identity and trace path. Failed retrieval leaves device and host data intact.
use crate::{
    adb::AdbClient,
    perfetto::{self, DecodedTrace},
};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerfettoOwner {
    pub serial: String,
    pub boot_id: String,
    pub token: String,
    pub remote_config: String,
    pub remote_trace: String,
    pub pid: Option<u32>,
    pub process_start_ticks: Option<u64>,
    pub duration_ms: u64,
    pub local_trace: PathBuf,
}

#[derive(Debug)]
pub struct PerfettoCapture {
    client: AdbClient,
    pub owner: PerfettoOwner,
    manifest: PathBuf,
}

#[derive(Debug, thiserror::Error)]
#[error("Perfetto startup failed after launch was requested: {cause}")]
pub struct StartupFailure {
    pub capture: Box<PerfettoCapture>,
    #[source]
    pub cause: anyhow::Error,
}

fn config(duration_ms: u64) -> String {
    format!(
        r#"buffers {{ size_kb: 16384 fill_policy: RING_BUFFER }}
duration_ms: {duration_ms}
write_into_file: true
file_write_period_ms: 1000
max_file_size_bytes: 268435456
data_sources {{ config {{ name: "linux.ftrace" ftrace_config {{
 ftrace_events: "block/block_rq_issue"
 ftrace_events: "block/block_rq_complete"
 ftrace_events: "block/block_rq_insert"
 ftrace_events: "block/block_rq_requeue"
 drain_period_ms: 100
}} }} }}
data_sources {{ config {{ name: "linux.process_stats" process_stats_config {{
 scan_all_processes_on_start: true
 record_process_age: true
}} }} }}
"#
    )
}

pub fn process_identity(stat: &str) -> Option<(char, u64)> {
    let tail = stat.get(stat.rfind(')')? + 1..)?;
    let fields: Vec<_> = tail.split_whitespace().collect();
    Some((
        fields.first()?.chars().next()?,
        fields.get(19)?.parse().ok()?,
    ))
}

impl PerfettoCapture {
    pub fn start(
        client: AdbClient,
        serial: &str,
        directory: &Path,
        duration_ms: u64,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            (1_000..=3_600_000).contains(&duration_ms),
            "Perfetto safety duration must be between 1 s and 1 hour"
        );
        std::fs::create_dir_all(directory)?;
        let token = uuid::Uuid::new_v4().to_string();
        let boot_id =
            client.unprivileged_text(serial, &["cat", "/proc/sys/kernel/random/boot_id"])?;
        anyhow::ensure!(!boot_id.is_empty(), "Device boot identity is unavailable");
        let mut capture = Self {
            client,
            owner: PerfettoOwner {
                serial: serial.into(),
                boot_id,
                remote_config: format!("/data/misc/perfetto-configs/aebpf-{token}.pbtxt"),
                remote_trace: format!("/data/misc/perfetto-traces/aebpf-{token}.pftrace"),
                pid: None,
                process_start_ticks: None,
                duration_ms,
                local_trace: directory.join("capture.pftrace"),
                token,
            },
            manifest: directory.join("perfetto-owner.json"),
        };
        // Refuse accidental raw-session overwrite before starting the phone.
        anyhow::ensure!(
            !capture.owner.local_trace.exists() && !capture.manifest.exists(),
            "Capture directory already contains a Perfetto session; choose a new session directory"
        );
        let config_path = directory.join("perfetto-config.pbtxt");
        std::fs::write(&config_path, config(duration_ms))?;
        capture.persist()?;
        capture
            .client
            .push_file(serial, &config_path, &capture.owner.remote_config)?;
        let launched = (|| -> anyhow::Result<()> {
            let output = capture.client.unprivileged_output(
                serial,
                &[
                    "perfetto",
                    "--txt",
                    "-c",
                    &capture.owner.remote_config,
                    "-o",
                    &capture.owner.remote_trace,
                    "--background-wait",
                ],
            )?;
            let result = String::from_utf8_lossy(&output.stdout);
            capture.owner.pid = result
                .lines()
                .find_map(|s| s.trim().parse::<u32>().ok())
                .filter(|p| *p > 1);
            capture.persist()?;
            anyhow::ensure!(
                output.status.success(),
                "Perfetto launch returned {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            );
            let pid = capture.owner.pid.ok_or_else(||anyhow::anyhow!("Perfetto did not return its owned PID; finite trace and recovery manifest retained"))?;
            let stat = capture
                .client
                .unprivileged_text(serial, &["cat", &format!("/proc/{pid}/stat")])?;
            let (_, ticks) = process_identity(&stat).ok_or_else(|| {
                anyhow::anyhow!(
                    "Unable to identify Perfetto process lifetime; recovery manifest retained"
                )
            })?;
            capture.owner.process_start_ticks = Some(ticks);
            capture.persist()?;
            anyhow::ensure!(
                capture.owned_process_alive()?,
                "Perfetto exited before readiness could be confirmed"
            );
            Ok(())
        })();
        if let Err(cause) = launched {
            return Err(StartupFailure {
                capture: Box::new(capture),
                cause,
            }
            .into());
        }
        Ok(capture)
    }
    fn persist(&self) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec_pretty(&self.owner)?;
        let mut file = std::fs::File::create(&self.manifest)?;
        use std::io::Write;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(())
    }
    /// Reopen a recoverable session. Validates owned paths before any action.
    pub fn recover(client: AdbClient, manifest: &Path) -> anyhow::Result<Self> {
        let owner: PerfettoOwner = serde_json::from_slice(&std::fs::read(manifest)?)?;
        let token = uuid::Uuid::parse_str(&owner.token)?.to_string();
        anyhow::ensure!(
            owner.remote_trace == format!("/data/misc/perfetto-traces/aebpf-{token}.pftrace")
                && owner.remote_config
                    == format!("/data/misc/perfetto-configs/aebpf-{token}.pbtxt"),
            "Recovery manifest contains unexpected remote paths"
        );
        let directory = manifest
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Missing recovery directory"))?;
        anyhow::ensure!(
            owner.local_trace == directory.join("capture.pftrace"),
            "Recovery trace must remain beside its manifest"
        );
        Ok(Self {
            client,
            owner,
            manifest: manifest.into(),
        })
    }
    pub fn owned_process_alive(&self) -> anyhow::Result<bool> {
        let serial = &self.owner.serial;
        let boot = self
            .client
            .unprivileged_text(serial, &["cat", "/proc/sys/kernel/random/boot_id"])?;
        anyhow::ensure!(
            boot == self.owner.boot_id,
            "Device rebooted; previous raw trace is preserved, but its process must not be signalled"
        );
        let pid = self
            .owner
            .pid
            .ok_or_else(|| anyhow::anyhow!("Capture PID was not confirmed"))?;
        // First establish connectivity, then distinguish absent proc entries.
        let present = self.client.unprivileged_text(
            serial,
            &[
                "sh",
                "-c",
                &format!("if test -e /proc/{pid}/stat; then echo present; else echo absent; fi"),
            ],
        )?;
        if present == "absent" {
            return Ok(false);
        }
        let stat = self
            .client
            .unprivileged_text(serial, &["cat", &format!("/proc/{pid}/stat")])?;
        let (state, ticks) =
            process_identity(&stat).ok_or_else(|| anyhow::anyhow!("Malformed process identity"))?;
        if Some(ticks) != self.owner.process_start_ticks {
            return Ok(false);
        }
        if state == 'Z' || state == 'X' {
            return Ok(false);
        }
        let command = self
            .client
            .unprivileged_text(serial, &["cat", &format!("/proc/{pid}/cmdline")])?;
        anyhow::ensure!(
            command.split('\0').any(|s| s == self.owner.remote_trace)
                && command.split('\0').any(|s| s == self.owner.remote_config),
            "PID no longer identifies the owned Perfetto command; refusing to signal it"
        );
        Ok(true)
    }
    pub fn stop_and_pull(&self) -> anyhow::Result<DecodedTrace> {
        if self.owned_process_alive()? {
            self.client.unprivileged_text(
                &self.owner.serial,
                &["kill", "-INT", &self.owner.pid.unwrap().to_string()],
            )?;
        }
        let started = Instant::now();
        while self.owned_process_alive()? {
            anyhow::ensure!(
                started.elapsed() < Duration::from_secs(15),
                "Perfetto is still flushing; raw trace and recovery manifest retained. Retry recovery after it finishes"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        // Process termination closes its descriptors. The trace's final flush
        // evidence is also checked, rather than assuming kill returned a file.
        self.pull()
    }
    /// After a reboot, only retrieve the nonce-scoped trace. Never signal a PID
    /// from a previous boot, even when the current phone reused its number.
    pub fn recover_and_pull(&mut self) -> anyhow::Result<DecodedTrace> {
        let boot = self.client.unprivileged_text(
            &self.owner.serial,
            &["cat", "/proc/sys/kernel/random/boot_id"],
        )?;
        anyhow::ensure!(
            !boot.is_empty(),
            "Device boot identity is unavailable; reconnect the original phone"
        );
        if boot != self.owner.boot_id {
            return self.pull();
        }
        if !self.establish_identity()? {
            return self.pull();
        }
        self.stop_and_pull()
    }

    /// A launch can fork a client before returning an error or losing its PID
    /// output. Reacquire only a unique process with both nonce-owned arguments
    /// and a stable lifetime, never an arbitrary `pidof` match.
    fn establish_identity(&mut self) -> anyhow::Result<bool> {
        if self.owner.pid.is_some() && self.owner.process_start_ticks.is_some() {
            return Ok(true);
        }
        let serial = &self.owner.serial;
        let boot = self
            .client
            .unprivileged_text(serial, &["cat", "/proc/sys/kernel/random/boot_id"])?;
        anyhow::ensure!(
            boot == self.owner.boot_id,
            "Device rebooted; do not signal a previous boot's process"
        );
        let output = self
            .client
            .unprivileged_output(serial, &["pidof", "perfetto"])?;
        anyhow::ensure!(
            output.status.success()
                || (output.status.code() == Some(1) && output.stderr.is_empty()),
            "Cannot enumerate Perfetto processes: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8_lossy(&output.stdout);
        let mut pids = std::collections::BTreeSet::new();
        for value in text.split_whitespace() {
            let pid = value.parse::<u32>()?;
            anyhow::ensure!(
                pid > 1 && pids.len() < 128,
                "Invalid or excessive Perfetto process candidates"
            );
            pids.insert(pid);
        }
        let mut found = None;
        for pid in pids {
            let stat = format!("/proc/{pid}/stat");
            let before = self.client.unprivileged_text(serial, &["cat", &stat])?;
            let before = process_identity(&before)
                .ok_or_else(|| anyhow::anyhow!("Malformed process lifetime"))?;
            let command = self
                .client
                .unprivileged_text(serial, &["cat", &format!("/proc/{pid}/cmdline")])?;
            if !command.split('\0').any(|s| s == self.owner.remote_config)
                || !command.split('\0').any(|s| s == self.owner.remote_trace)
            {
                continue;
            }
            let after = self.client.unprivileged_text(serial, &["cat", &stat])?;
            let after = process_identity(&after)
                .ok_or_else(|| anyhow::anyhow!("Malformed process lifetime"))?;
            anyhow::ensure!(
                after.1 == before.1,
                "Process lifetime changed during recovery identification"
            );
            if matches!(after.0, 'Z' | 'X') {
                continue;
            }
            anyhow::ensure!(
                found.is_none(),
                "Multiple processes reference this trace; ownership is ambiguous"
            );
            found = Some((pid, before.1));
        }
        if let Some((pid, ticks)) = found {
            self.owner.pid = Some(pid);
            self.owner.process_start_ticks = Some(ticks);
            self.persist()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn finish_failed_start(&mut self) -> anyhow::Result<Option<DecodedTrace>> {
        if self.establish_identity()? {
            return self.stop_and_pull().map(Some);
        }
        let present = self.client.unprivileged_output(
            &self.owner.serial,
            &["test", "-f", &self.owner.remote_trace],
        )?;
        if present.status.success() {
            return self.pull().map(Some);
        }
        anyhow::ensure!(
            present.status.code() == Some(1) && present.stderr.is_empty(),
            "Cannot check the failed capture's raw trace"
        );
        Ok(None)
    }
    pub fn pull(&self) -> anyhow::Result<DecodedTrace> {
        let staging = self.owner.local_trace.with_extension("pftrace.partial");
        self.client
            .pull_file(&self.owner.serial, &self.owner.remote_trace, &staging)?;
        let decoded = perfetto::decode(std::io::BufReader::new(std::fs::File::open(&staging)?));
        // Existing complete source is never replaced by a failed retrieval.
        if self.owner.local_trace.exists() {
            anyhow::ensure!(
                !decoded.quality.truncated && decoded.quality.ftrace_end_seen,
                "Recovery download is incomplete; existing raw trace and partial download preserved"
            );
            let backup = self
                .owner
                .local_trace
                .with_extension(format!("{}.previous.pftrace", uuid::Uuid::new_v4()));
            std::fs::rename(&self.owner.local_trace, backup)?;
        }
        std::fs::rename(staging, &self.owner.local_trace)?;
        Ok(decoded)
    }
}
