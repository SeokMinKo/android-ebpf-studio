use std::{
    collections::HashMap,
    io::Read,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use thiserror::Error;

const REMOTE_AGENT: &str = "/data/local/tmp/android-ebpf-studio/agent";
const REMOTE_BPF: &str = "/data/local/tmp/android-ebpf-studio/storage-ebpf.o";

fn adb_process(program: impl AsRef<std::ffi::OsStr>) -> Command {
    let command = Command::new(program);
    #[cfg(windows)]
    let command = {
        let mut command = command;
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW: no flashing ADB consoles.
        command
    };
    command
}

pub fn is_root_uid(output: &str) -> bool {
    output.trim() == "0"
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceState {
    Device,
    Unauthorized,
    Offline,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdbDevice {
    pub serial: String,
    pub state: DeviceState,
    pub model: Option<String>,
    pub product: Option<String>,
    pub device: Option<String>,
}

pub fn parse_devices(output: &str) -> Vec<AdbDevice> {
    output
        .lines()
        .skip_while(|line| !line.starts_with("List of devices"))
        .skip(1)
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let serial = fields.next()?;
            let raw_state = fields.next()?;
            if !is_valid_serial(serial) {
                return None;
            }
            let mut metadata = HashMap::new();
            for field in fields {
                if let Some((key, value)) = field.split_once(':') {
                    metadata.insert(key, value);
                }
            }
            Some(AdbDevice {
                serial: serial.to_owned(),
                state: match raw_state {
                    "device" => DeviceState::Device,
                    "unauthorized" => DeviceState::Unauthorized,
                    "offline" => DeviceState::Offline,
                    _ => DeviceState::Other,
                },
                model: metadata.get("model").map(|value| (*value).to_owned()),
                product: metadata.get("product").map(|value| (*value).to_owned()),
                device: metadata.get("device").map(|value| (*value).to_owned()),
            })
        })
        .collect()
}

fn is_valid_serial(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
}

impl CommandSpec {
    fn execute(&self) -> std::io::Result<Output> {
        let mut child = adb_process(&self.program)
            .args(&self.args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();
        let out = thread::spawn(move || {
            let mut v = Vec::new();
            stdout.read_to_end(&mut v).map(|_| v)
        });
        let err = thread::spawn(move || {
            let mut v = Vec::new();
            stderr.read_to_end(&mut v).map(|_| v)
        });
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if started.elapsed() > Duration::from_secs(20) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "ADB timed out after 20 seconds; reconnect or approve the root prompt and retry Start",
                ));
            }
            thread::sleep(Duration::from_millis(20));
        };
        Ok(Output {
            status,
            stdout: out
                .join()
                .map_err(|_| std::io::Error::other("stdout reader failed"))??,
            stderr: err
                .join()
                .map_err(|_| std::io::Error::other("stderr reader failed"))??,
        })
    }
}

#[derive(Debug, Clone)]
pub struct AdbCommandBuilder {
    adb_path: PathBuf,
    serial: String,
}

impl AdbCommandBuilder {
    pub fn new(serial: impl Into<String>) -> Result<Self, AdbError> {
        Self::with_adb("adb", serial)
    }

    pub fn with_adb(
        adb_path: impl Into<PathBuf>,
        serial: impl Into<String>,
    ) -> Result<Self, AdbError> {
        let serial = serial.into();
        if !is_valid_serial(&serial) {
            return Err(AdbError::InvalidSerial);
        }
        Ok(Self {
            adb_path: adb_path.into(),
            serial,
        })
    }

    pub fn shell(&self, remote_args: &[&str]) -> CommandSpec {
        let mut args = vec!["-s".into(), self.serial.clone(), "shell".into()];
        args.extend(remote_args.iter().map(|value| (*value).to_owned()));
        CommandSpec {
            program: self.adb_path.to_string_lossy().into_owned(),
            args,
        }
    }

    pub fn host(&self, args: &[&str]) -> CommandSpec {
        let mut bound = vec!["-s".into(), self.serial.clone()];
        bound.extend(args.iter().map(|value| (*value).to_owned()));
        CommandSpec {
            program: self.adb_path.to_string_lossy().into_owned(),
            args: bound,
        }
    }

    pub fn serial(&self) -> &str {
        &self.serial
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RootMethod {
    #[default]
    Shell,
    SuCommand,
    SuUid,
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

impl AdbCommandBuilder {
    pub fn root_shell(&self, method: RootMethod, args: &[&str]) -> CommandSpec {
        let command = args
            .iter()
            .map(|v| shell_quote(v))
            .collect::<Vec<_>>()
            .join(" ");
        let command = match method {
            RootMethod::Shell => command,
            RootMethod::SuCommand => format!("su -c {}", shell_quote(&command)),
            RootMethod::SuUid => format!("su 0 sh -c {}", shell_quote(&command)),
        };
        self.shell(&[&command])
    }
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PreflightReport {
    /// A preflight pass is not proof that the verifier/collector can start.
    #[serde(default)]
    pub ebpf_start_error: Option<String>,
    #[serde(default)]
    pub perfetto: bool,
    #[serde(default)]
    pub perfetto_version: String,
    pub root: bool,
    pub root_method: RootMethod,
    pub serial: String,
    pub model: String,
    pub boot_id: String,
    pub build_fingerprint: String,
    pub mountinfo: String,
    pub filesystems: String,
    pub block_devices: String,
    pub trace_root: String,
    pub abi: String,
    pub android_version: String,
    pub kernel_release: String,
    pub btf: bool,
    pub tracefs: bool,
    pub block_issue: bool,
    pub block_complete: bool,
    pub block_insert: bool,
    pub raw_syscalls: bool,
    pub ufs_events: Vec<String>,
    pub scsi_events: Vec<String>,
    pub fs_events: Vec<String>,
    pub diagnostics: Vec<String>,
}

impl PreflightReport {
    pub fn full_ebpf_ready(&self) -> bool {
        self.root
            && self.ebpf_start_error.is_none()
            && self.abi == "arm64-v8a"
            && self.tracefs
            && self.block_issue
            && self.block_complete
    }
}

#[derive(Debug, Error)]
pub enum AdbError {
    #[error("invalid ADB serial")]
    InvalidSerial,
    #[error("ADB I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("ADB command failed ({operation}): {message}")]
    Command { operation: String, message: String },
    #[error("local artifact does not exist: {0}")]
    MissingArtifact(String),
}

#[derive(Debug, Clone)]
pub struct AdbClient {
    adb_path: PathBuf,
}

impl Default for AdbClient {
    fn default() -> Self {
        Self::new("adb")
    }
}

impl AdbClient {
    pub(crate) fn unprivileged_output(
        &self,
        serial: &str,
        args: &[&str],
    ) -> Result<Output, AdbError> {
        let builder = AdbCommandBuilder::with_adb(&self.adb_path, serial)?;
        Ok(builder.root_shell(RootMethod::Shell, args).execute()?)
    }
    pub(crate) fn unprivileged_text(
        &self,
        serial: &str,
        args: &[&str],
    ) -> Result<String, AdbError> {
        let builder = AdbCommandBuilder::with_adb(&self.adb_path, serial)?;
        self.root_text(&builder, RootMethod::Shell, args)
    }

    pub(crate) fn push_file(
        &self,
        serial: &str,
        local: &Path,
        remote: &str,
    ) -> Result<(), AdbError> {
        let builder = AdbCommandBuilder::with_adb(&self.adb_path, serial)?;
        self.push(&builder, local, remote)
    }

    pub(crate) fn pull_file(
        &self,
        serial: &str,
        remote: &str,
        local: &Path,
    ) -> Result<(), AdbError> {
        let builder = AdbCommandBuilder::with_adb(&self.adb_path, serial)?;
        self.run(
            "pull Perfetto trace",
            builder.host(&["pull", remote, &local.to_string_lossy()]),
        )
        .map(|_| ())
    }

    pub fn new(adb_path: impl Into<PathBuf>) -> Self {
        Self {
            adb_path: adb_path.into(),
        }
    }

    pub fn list_devices(&self) -> Result<Vec<AdbDevice>, AdbError> {
        let output = CommandSpec {
            program: self.adb_path.to_string_lossy().into_owned(),
            args: vec!["devices".into(), "-l".into()],
        }
        .execute()?;
        require_success("devices", &output)?;
        Ok(parse_devices(&String::from_utf8_lossy(&output.stdout)))
    }

    pub fn preflight(&self, serial: &str) -> Result<PreflightReport, AdbError> {
        let builder = AdbCommandBuilder::with_adb(&self.adb_path, serial)?;
        let method = self.detect_root(&builder);
        let mut report = PreflightReport {
            serial: serial.into(),
            ..Default::default()
        };
        let method = match method {
            Ok(value) => {
                report.root = true;
                value
            }
            Err(error) => {
                report.diagnostics.push(format!(
                    "Root unavailable; checking unprivileged capture support ({error})"
                ));
                RootMethod::Shell
            }
        };
        report.root_method = method;
        report.model = self.root_text(&builder, method, &["getprop", "ro.product.model"])?;
        report.boot_id = self.root_text(
            &builder,
            method,
            &["cat", "/proc/sys/kernel/random/boot_id"],
        )?;
        report.build_fingerprint =
            self.root_text(&builder, method, &["getprop", "ro.build.fingerprint"])?;
        report.mountinfo = self.root_text(&builder, method, &["cat", "/proc/self/mountinfo"])?;
        report.filesystems = self.root_text(&builder, method, &["cat", "/proc/filesystems"])?;
        report.block_devices = self.root_text(&builder, method, &["cat", "/proc/partitions"])?;
        report.trace_root = if self.root_bool(
            &builder,
            method,
            &["test", "-d", "/sys/kernel/tracing/events"],
        )? {
            "/sys/kernel/tracing".into()
        } else {
            "/sys/kernel/debug/tracing".into()
        };
        report.abi = self.root_text(&builder, method, &["getprop", "ro.product.cpu.abi"])?;
        report.android_version =
            self.root_text(&builder, method, &["getprop", "ro.build.version.release"])?;
        report.kernel_release = self.root_text(&builder, method, &["uname", "-r"])?;
        report.btf =
            self.root_bool(&builder, method, &["test", "-r", "/sys/kernel/btf/vmlinux"])?;
        report.tracefs = self.root_bool(
            &builder,
            method,
            &["test", "-d", &format!("{}/events", report.trace_root)],
        )?;
        report.block_issue = self.root_bool(
            &builder,
            method,
            &[
                "test",
                "-r",
                &format!("{}/events/block/block_rq_issue/format", report.trace_root),
            ],
        )?;
        report.block_complete = self.root_bool(
            &builder,
            method,
            &[
                "test",
                "-r",
                &format!(
                    "{}/events/block/block_rq_complete/format",
                    report.trace_root
                ),
            ],
        )?;
        report.block_insert = self.root_bool(
            &builder,
            method,
            &[
                "test",
                "-r",
                &format!("{}/events/block/block_rq_insert/format", report.trace_root),
            ],
        )?;
        report.raw_syscalls = self.root_bool(
            &builder,
            method,
            &[
                "test",
                "-r",
                &format!("{}/events/raw_syscalls/sys_enter/format", report.trace_root),
            ],
        )? && self.root_bool(
            &builder,
            method,
            &[
                "test",
                "-r",
                &format!("{}/events/raw_syscalls/sys_exit/format", report.trace_root),
            ],
        )?;
        let events = self
            .root_text(
                &builder,
                method,
                &[
                    "find",
                    &format!("{}/events", report.trace_root),
                    "-maxdepth",
                    "2",
                    "-type",
                    "d",
                ],
            )
            .unwrap_or_default();
        report.ufs_events = events
            .lines()
            .filter(|line| line.to_ascii_lowercase().contains("ufs"))
            .take(128)
            .map(str::to_owned)
            .collect();
        report.scsi_events = events
            .lines()
            .filter(|line| line.to_ascii_lowercase().contains("scsi"))
            .take(128)
            .map(str::to_owned)
            .collect();
        report.fs_events = events
            .lines()
            .filter(|line| {
                let lower = line.to_ascii_lowercase();
                lower.contains("f2fs") || lower.contains("ext4")
            })
            .take(256)
            .map(str::to_owned)
            .collect();
        // Detect fallbacks even when root tracepoints are readable: attach can
        // still fail later because of the verifier, policy or collector startup.
        if let Ok(query) = self.root_text(&builder, RootMethod::Shell, &["perfetto", "--query"]) {
            report.perfetto = query.contains("linux.ftrace");
            report.perfetto_version = query
                .lines()
                .find(|line| line.contains("Perfetto v"))
                .unwrap_or("Perfetto service available")
                .to_owned();
        }
        if !report.full_ebpf_ready() {
            report.diagnostics.push("Full block tracing unavailable: requires arm64 agent and readable issue/complete tracepoints. Root alone does not prove BPF verifier/attach support.".into());
        }
        Ok(report)
    }

    pub fn disk_stats(
        &self,
        serial: &str,
        method: RootMethod,
    ) -> Result<(String, String), AdbError> {
        let builder = AdbCommandBuilder::with_adb(&self.adb_path, serial)?;
        let boot = self.root_text(
            &builder,
            method,
            &["cat", "/proc/sys/kernel/random/boot_id"],
        )?;
        let raw = self.root_text(&builder, method, &["cat", "/proc/diskstats"])?;
        Ok((boot, raw))
    }

    pub fn deploy(
        &self,
        serial: &str,
        local_agent: &Path,
        local_bpf: &Path,
    ) -> Result<(), AdbError> {
        for artifact in [local_agent, local_bpf] {
            if !artifact.is_file() {
                return Err(AdbError::MissingArtifact(artifact.display().to_string()));
            }
        }
        let builder = AdbCommandBuilder::with_adb(&self.adb_path, serial)?;
        let method = self.detect_root(&builder)?;
        self.run(
            "create remote directory",
            builder.root_shell(
                method,
                &["mkdir", "-p", "/data/local/tmp/android-ebpf-studio"],
            ),
        )?;
        self.push(&builder, local_agent, REMOTE_AGENT)?;
        self.push(&builder, local_bpf, REMOTE_BPF)?;
        self.run(
            "chmod agent",
            builder.root_shell(method, &["chmod", "0755", REMOTE_AGENT]),
        )?;
        Ok(())
    }

    pub fn start_capture(
        &self,
        serial: &str,
        session_id: &str,
        log_level: &str,
    ) -> Result<Child, AdbError> {
        let builder = AdbCommandBuilder::with_adb(&self.adb_path, serial)?;
        let method = self.detect_root(&builder)?;
        let spec = builder.root_shell(
            method,
            &[
                REMOTE_AGENT,
                "capture",
                "--bpf-object",
                REMOTE_BPF,
                "--health-interval-ms",
                "1000",
                "--session-id",
                session_id,
                "--log-level",
                log_level,
            ],
        );
        Ok(adb_process(spec.program)
            .args(spec.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?)
    }

    fn detect_root(&self, builder: &AdbCommandBuilder) -> Result<RootMethod, AdbError> {
        for method in [RootMethod::Shell, RootMethod::SuCommand, RootMethod::SuUid] {
            if self
                .root_text(builder, method, &["id", "-u"])
                .is_ok_and(|uid| is_root_uid(&uid))
            {
                return Ok(method);
            }
        }
        // Try adbd restart only after existing shell and su root have failed.
        let _ = self.run("enable adbd root", builder.host(&["root"]));
        let _ = self.run(
            "wait for root reconnect",
            builder.host(&["wait-for-device"]),
        );
        if self
            .root_text(builder, RootMethod::Shell, &["id", "-u"])
            .is_ok_and(|uid| is_root_uid(&uid))
        {
            return Ok(RootMethod::Shell);
        }
        Err(AdbError::Command { operation: "root detection".into(), message: "Approve USB debugging and the su/root prompt on the phone, then retry Start. Shell, su -c, su 0 and adb root did not provide UID 0.".into() })
    }

    fn root_text(
        &self,
        builder: &AdbCommandBuilder,
        method: RootMethod,
        args: &[&str],
    ) -> Result<String, AdbError> {
        let output = self.run("root probe", builder.root_shell(method, args))?;
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }
    fn root_bool(
        &self,
        builder: &AdbCommandBuilder,
        method: RootMethod,
        args: &[&str],
    ) -> Result<bool, AdbError> {
        Ok(builder.root_shell(method, args).execute()?.status.success())
    }

    fn push(
        &self,
        builder: &AdbCommandBuilder,
        local: &Path,
        remote: &str,
    ) -> Result<(), AdbError> {
        let local = local.to_string_lossy();
        self.run("push artifact", builder.host(&["push", &local, remote]))
            .map(|_| ())
    }

    fn run(&self, operation: &str, spec: CommandSpec) -> Result<Output, AdbError> {
        let output = spec.execute()?;
        require_success(operation, &output)?;
        Ok(output)
    }
}

fn require_success(operation: &str, output: &Output) -> Result<(), AdbError> {
    if output.status.success() {
        Ok(())
    } else {
        Err(AdbError::Command {
            operation: operation.to_owned(),
            message: bounded_stderr(output),
        })
    }
}

fn bounded_stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr)
        .chars()
        .take(4096)
        .collect::<String>()
        .trim()
        .to_owned()
}
