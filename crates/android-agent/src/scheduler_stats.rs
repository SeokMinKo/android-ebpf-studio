//! Capture-scoped scheduler accounting. The tracepoint can attach while this
//! global switch is disabled; only a verified write enables the measurement.
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

pub struct SchedulerStatsGuard {
    path: PathBuf,
    owns_enable: bool,
}
impl SchedulerStatsGuard {
    pub fn enable(path: &Path) -> Result<Self> {
        let before = std::fs::read_to_string(path).context("scheduler stats switch unavailable")?;
        let mut guard = Self {
            path: path.into(),
            owns_enable: false,
        };
        match before.trim() {
            "1" => Ok(guard),
            "0" => {
                guard.owns_enable = true;
                std::fs::write(path, b"1\n").context("cannot enable scheduler stats")?;
                if std::fs::read_to_string(path)?.trim() != "1" {
                    bail!("scheduler stats enable did not read back as 1");
                }
                Ok(guard)
            }
            _ => bail!("unexpected scheduler stats switch value; unchanged"),
        }
    }
    pub fn changed(&self) -> bool {
        self.owns_enable
    }
    pub fn restore(&mut self) -> Result<bool> {
        if !self.owns_enable {
            return Ok(false);
        }
        // Do not overwrite an externally changed value.
        if std::fs::read_to_string(&self.path)?.trim() == "1" {
            std::fs::write(&self.path, b"0\n")?;
            if std::fs::read_to_string(&self.path)?.trim() != "0" {
                bail!("scheduler stats restore did not read back as 0");
            }
        }
        self.owns_enable = false;
        Ok(true)
    }
}
impl Drop for SchedulerStatsGuard {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn path() -> PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "scheduler-switch-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))
    }
    #[test]
    fn verifies_enable_and_restores_only_owned_change() {
        for (original, changed) in [("0", true), ("1", false)] {
            let path = path();
            std::fs::write(&path, original).unwrap();
            {
                let mut guard = SchedulerStatsGuard::enable(&path).unwrap();
                assert_eq!(guard.changed(), changed);
                assert_eq!(std::fs::read_to_string(&path).unwrap().trim(), "1");
                assert_eq!(guard.restore().unwrap(), changed);
            }
            assert_eq!(std::fs::read_to_string(&path).unwrap().trim(), original);
            std::fs::remove_file(path).unwrap();
        }
    }
    #[test]
    fn unwinding_restores_and_unknown_values_are_not_modified() {
        let path = path();
        std::fs::write(&path, "0").unwrap();
        let unwind = std::panic::catch_unwind(|| {
            let _guard = SchedulerStatsGuard::enable(&path).unwrap();
            panic!("capture failed after enabling scheduler stats");
        });
        assert!(unwind.is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap().trim(), "0");
        std::fs::write(&path, "unrecognized").unwrap();
        assert!(SchedulerStatsGuard::enable(&path).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "unrecognized");
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn external_change_is_preserved_and_restore_is_idempotent() {
        let path = path();
        std::fs::write(&path, "0").unwrap();
        let mut guard = SchedulerStatsGuard::enable(&path).unwrap();
        std::fs::write(&path, "external").unwrap();
        assert!(guard.restore().unwrap());
        assert!(!guard.restore().unwrap());
        drop(guard);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "external");
        std::fs::remove_file(path).unwrap();
    }
}
