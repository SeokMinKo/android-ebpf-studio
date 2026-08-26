use std::{
    fs::{self, File, OpenOptions},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

use android_ebpf_protocol::{DiagnosticLevel, DiagnosticRecord, SCHEMA_VERSION};

pub const DEFAULT_LOG_BYTES: u64 = 20 * 1024 * 1024;
pub const DEFAULT_LOG_FILES: usize = 5;

pub struct RotatingJsonl {
    path: PathBuf,
    writer: BufWriter<File>,
    bytes: u64,
    max_bytes: u64,
    max_files: usize,
}

impl RotatingJsonl {
    pub fn create(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        Self::with_limits(path, DEFAULT_LOG_BYTES, DEFAULT_LOG_FILES)
    }

    pub fn with_limits(
        path: impl Into<PathBuf>,
        max_bytes: u64,
        max_files: usize,
    ) -> std::io::Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let writer = open_append(&path)?;
        let bytes = writer.get_ref().metadata()?.len();
        Ok(Self {
            path,
            writer,
            bytes,
            max_bytes: max_bytes.max(1),
            max_files: max_files.max(1),
        })
    }

    pub fn append(&mut self, record: &DiagnosticRecord) -> std::io::Result<()> {
        let record = sanitize_record(record.clone()).bounded();
        let mut json = serde_json::to_vec(&record).map_err(std::io::Error::other)?;
        json.push(b'\n');
        if self.bytes > 0 && self.bytes.saturating_add(json.len() as u64) > self.max_bytes {
            self.rotate()?;
        }
        self.writer.write_all(&json)?;
        self.writer.flush()?;
        self.bytes = self.bytes.saturating_add(json.len() as u64);
        Ok(())
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        self.writer.flush()?;
        for index in (1..self.max_files).rev() {
            let source = rotated_path(&self.path, index);
            let destination = rotated_path(&self.path, index + 1);
            if source.exists() {
                if destination.exists() {
                    fs::remove_file(&destination)?;
                }
                fs::rename(source, destination)?;
            }
        }
        let first = rotated_path(&self.path, 1);
        if first.exists() {
            fs::remove_file(&first)?;
        }
        if self.path.exists() {
            fs::rename(&self.path, first)?;
        }
        self.writer = open_append(&self.path)?;
        self.bytes = 0;
        Ok(())
    }
}

fn open_append(path: &Path) -> std::io::Result<BufWriter<File>> {
    Ok(BufWriter::new(
        OpenOptions::new().create(true).append(true).open(path)?,
    ))
}

fn rotated_path(path: &Path, index: usize) -> PathBuf {
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("log");
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("jsonl");
    path.with_file_name(format!("{stem}.{index}.{extension}"))
}

pub fn parse_agent_diagnostic(line: &str, session_id: &str) -> DiagnosticRecord {
    sanitize_record(
        serde_json::from_str::<DiagnosticRecord>(line)
            .unwrap_or_else(|error| DiagnosticRecord {
                schema_version: SCHEMA_VERSION,
                ts_unix_ms: chrono::Utc::now().timestamp_millis(),
                level: DiagnosticLevel::Warn,
                component: "desktop.capture".into(),
                event: "agent.diagnostic.decode".into(),
                session_id: session_id.into(),
                boot_id: String::new(),
                outcome: "rejected".into(),
                code: "AGENT_DIAGNOSTIC_INVALID".into(),
                correlation_id: None,
                node_id: None,
                probe: None,
                duration_ms: None,
                count: None,
                detail: Some(format!("{error}; line={line}")),
            })
            .bounded(),
    )
}

pub fn host_record(
    session_id: &str,
    level: DiagnosticLevel,
    event: &str,
    code: &str,
    outcome: &str,
    detail: Option<String>,
) -> DiagnosticRecord {
    sanitize_record(
        DiagnosticRecord {
            schema_version: SCHEMA_VERSION,
            ts_unix_ms: chrono::Utc::now().timestamp_millis(),
            level,
            component: "desktop.capture".into(),
            event: event.into(),
            session_id: session_id.into(),
            boot_id: String::new(),
            outcome: outcome.into(),
            code: code.into(),
            correlation_id: None,
            node_id: None,
            probe: None,
            duration_ms: None,
            count: None,
            detail,
        }
        .bounded(),
    )
}

fn sanitize_record(mut record: DiagnosticRecord) -> DiagnosticRecord {
    if let Some(detail) = &mut record.detail {
        *detail = detail
            .split_whitespace()
            .map(|token| {
                let windows_path = token.as_bytes().get(1) == Some(&b':')
                    && (token.contains('\\') || token.contains('/'));
                if token.contains("/data/")
                    || token.contains("/storage/")
                    || token.starts_with('/')
                    || windows_path
                {
                    "<redacted-path>"
                } else {
                    token
                }
            })
            .collect::<Vec<_>>()
            .join(" ");
    }
    record
}

pub fn export_bundle(
    destination: &Path,
    log_directory: &Path,
    session_path: Option<&Path>,
    include_raw_session: bool,
    metadata: Option<&serde_json::Value>,
) -> std::io::Result<PathBuf> {
    fs::create_dir_all(destination)?;
    let manifest = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "studio_version": env!("CARGO_PKG_VERSION"),
        "created_unix_ms": chrono::Utc::now().timestamp_millis(),
        "raw_session_included": include_raw_session,
        "privacy": "Diagnostic details are redacted; raw session may contain file paths.",
    });
    fs::write(
        destination.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).map_err(std::io::Error::other)?,
    )?;
    if let Some(metadata) = metadata {
        fs::write(
            destination.join("capture-profile.json"),
            serde_json::to_vec_pretty(metadata).map_err(std::io::Error::other)?,
        )?;
    }
    if log_directory.is_dir() {
        for entry in fs::read_dir(log_directory)?.flatten() {
            if entry.path().is_file() {
                fs::copy(entry.path(), destination.join(entry.file_name()))?;
            }
        }
    }
    if include_raw_session
        && let Some(session) = session_path
        && session.is_file()
    {
        fs::copy(session, destination.join("session.ndjson"))?;
    }
    Ok(destination.to_path_buf())
}
