use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
};

use thiserror::Error;

const REMOTE_AGENT: &str = "/data/local/tmp/android-ebpf-studio/agent";
const REMOTE_BPF: &str = "/data/local/tmp/android-ebpf-studio/storage-ebpf.o";

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
        Command::new(&self.program).args(&self.args).output()
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

#[derive(Debug, Clone, Default)]
pub struct PreflightReport {
    pub root: bool,
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
        self.root && self.tracefs && self.block_issue && self.block_complete
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
    pub fn new(adb_path: impl Into<PathBuf>) -> Self {
        Self {
            adb_path: adb_path.into(),
        }
    }

    pub fn list_devices(&self) -> Result<Vec<AdbDevice>, AdbError> {
        let output = Command::new(&self.adb_path)
            .args(["devices", "-l"])
            .output()?;
        require_success("devices", &output)?;
        Ok(parse_devices(&String::from_utf8_lossy(&output.stdout)))
    }

    pub fn preflight(&self, serial: &str) -> Result<PreflightReport, AdbError> {
        let builder = AdbCommandBuilder::with_adb(&self.adb_path, serial)?;
        let root_output = builder.host(&["root"]).execute()?;
        let mut report = PreflightReport {
            root: root_output.status.success(),
            ..PreflightReport::default()
        };
        if !root_output.status.success() {
            report.diagnostics.push(bounded_stderr(&root_output));
        }
        let _ = builder.host(&["wait-for-device"]).execute()?;
        report.abi = self.shell_text(&builder, &["getprop", "ro.product.cpu.abi"])?;
        report.android_version =
            self.shell_text(&builder, &["getprop", "ro.build.version.release"])?;
        report.kernel_release = self.shell_text(&builder, &["uname", "-r"])?;
        report.btf = self.shell_bool(&builder, &["test", "-r", "/sys/kernel/btf/vmlinux"])?;
        report.tracefs =
            self.shell_bool(&builder, &["test", "-d", "/sys/kernel/tracing/events"])?;
        report.block_issue = self.shell_bool(
            &builder,
            &[
                "test",
                "-r",
                "/sys/kernel/tracing/events/block/block_rq_issue/format",
            ],
        )?;
        report.block_complete = self.shell_bool(
            &builder,
            &[
                "test",
                "-r",
                "/sys/kernel/tracing/events/block/block_rq_complete/format",
            ],
        )?;
        report.block_insert = self.shell_bool(
            &builder,
            &[
                "test",
                "-r",
                "/sys/kernel/tracing/events/block/block_rq_insert/format",
            ],
        )?;
        report.raw_syscalls = self.shell_bool(
            &builder,
            &[
                "test",
                "-r",
                "/sys/kernel/tracing/events/raw_syscalls/sys_enter/format",
            ],
        )? && self.shell_bool(
            &builder,
            &[
                "test",
                "-r",
                "/sys/kernel/tracing/events/raw_syscalls/sys_exit/format",
            ],
        )?;
        let events = self.shell_text(
            &builder,
            &[
                "find",
                "/sys/kernel/tracing/events",
                "-maxdepth",
                "2",
                "-type",
                "d",
            ],
        )?;
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
        Ok(report)
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
        self.run(
            "create remote directory",
            builder.shell(&["mkdir", "-p", "/data/local/tmp/android-ebpf-studio"]),
        )?;
        self.push(&builder, local_agent, REMOTE_AGENT)?;
        self.push(&builder, local_bpf, REMOTE_BPF)?;
        self.run(
            "chmod agent",
            builder.shell(&["chmod", "0755", REMOTE_AGENT]),
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
        let spec = builder.shell(&[
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
        ]);
        Ok(Command::new(spec.program)
            .args(spec.args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?)
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

    fn shell_text(&self, builder: &AdbCommandBuilder, args: &[&str]) -> Result<String, AdbError> {
        let output = self.run("shell probe", builder.shell(args))?;
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }

    fn shell_bool(&self, builder: &AdbCommandBuilder, args: &[&str]) -> Result<bool, AdbError> {
        Ok(builder.shell(args).execute()?.status.success())
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
