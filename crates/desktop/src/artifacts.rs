use std::{
    env, fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturePaths {
    pub agent: PathBuf,
    pub bpf_object: PathBuf,
    pub session: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum CapturePathError {
    #[error(
        "Android agent was not found. Put `android-ebpf-agent` beside android-ebpf-studio.exe."
    )]
    AgentNotFound,
    #[error(
        "eBPF object was not found. Put `android-storage-ebpf.o` beside android-ebpf-studio.exe."
    )]
    BpfNotFound,
    #[error("cannot create session directory {path}: {source}")]
    SessionDirectory {
        path: String,
        source: std::io::Error,
    },
}

impl CapturePaths {
    pub fn discover() -> Result<Self, CapturePathError> {
        let executable =
            env::current_exe().unwrap_or_else(|_| PathBuf::from("android-ebpf-studio.exe"));
        let working_directory = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let session_root = default_session_root(&working_directory);
        Self::discover_from(&executable, &working_directory, &session_root)
    }

    pub fn discover_from(
        executable: &Path,
        working_directory: &Path,
        session_root: &Path,
    ) -> Result<Self, CapturePathError> {
        let executable_dir = executable.parent().unwrap_or(working_directory);
        let agent = first_file(&[
            executable_dir.join("android-ebpf-agent"),
            executable_dir.join("artifacts").join("android-ebpf-agent"),
            working_directory.join("android-ebpf-agent"),
            working_directory
                .join("target")
                .join("aarch64-linux-android")
                .join("release")
                .join("android-ebpf-agent"),
        ])
        .ok_or(CapturePathError::AgentNotFound)?;
        let bpf_object = first_file(&[
            executable_dir.join("android-storage-ebpf.o"),
            executable_dir
                .join("artifacts")
                .join("android-storage-ebpf.o"),
            working_directory.join("android-storage-ebpf.o"),
            working_directory
                .join("crates")
                .join("android-ebpf")
                .join("target")
                .join("bpfel-unknown-none")
                .join("release")
                .join("android-storage-ebpf"),
        ])
        .ok_or(CapturePathError::BpfNotFound)?;
        fs::create_dir_all(session_root).map_err(|source| CapturePathError::SessionDirectory {
            path: session_root.display().to_string(),
            source,
        })?;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let session = session_root.join(format!("android-storage-{timestamp}.ndjson"));
        Ok(Self {
            agent,
            bpf_object,
            session,
        })
    }
}

pub fn create_default_session_path() -> Result<PathBuf, CapturePathError> {
    let working_directory = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let session_root = default_session_root(&working_directory);
    fs::create_dir_all(&session_root).map_err(|source| CapturePathError::SessionDirectory {
        path: session_root.display().to_string(),
        source,
    })?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    Ok(session_root.join(format!("android-storage-{timestamp}.ndjson")))
}

fn default_session_root(working_directory: &Path) -> PathBuf {
    env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .map(|path| path.join("AndroidEbpfStudio").join("sessions"))
        .unwrap_or_else(|| working_directory.join("sessions"))
}

fn first_file(candidates: &[PathBuf]) -> Option<PathBuf> {
    candidates.iter().find(|path| path.is_file()).cloned()
}
