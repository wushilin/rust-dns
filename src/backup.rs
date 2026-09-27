//! Periodic online SQLite backups with rotation.
//!
//! Each run first verifies the live database (`PRAGMA quick_check`); a failing
//! check skips the backup and never prunes, so a corrupt database cannot rotate
//! good history away. The copy is written to a hidden temporary name and only
//! renamed to its final `rust-dns-<stamp>.db` name once complete, so partial
//! files never count toward `keep`. The first backup happens one full interval
//! after startup, so a crash-looping service does not churn through history.

use crate::config::BackupConfig;
use crate::storage::Storage;
use anyhow::Context;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

const PREFIX: &str = "rust-dns-";
const SUFFIX: &str = ".db";

/// Spawn the periodic backup task. Does nothing when backups are disabled
/// (empty `dir` or `keep == 0`).
pub fn spawn(storage: Arc<Storage>, cfg: BackupConfig) {
    if cfg.dir.as_os_str().is_empty() || cfg.keep == 0 {
        return;
    }
    tokio::spawn(async move {
        let hours = cfg.interval_hours.max(1);
        let period = Duration::from_secs(hours.saturating_mul(3600));
        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let storage = storage.clone();
            let job_cfg = cfg.clone();
            let result = tokio::task::spawn_blocking(move || run_once(&storage, &job_cfg)).await;
            match result {
                Ok(Ok(path)) => tracing::info!(
                    path = %path.display(),
                    keep = cfg.keep,
                    "database backup completed"
                ),
                Ok(Err(e)) => tracing::error!(error = %format!("{e:#}"), "database backup failed"),
                Err(e) => tracing::error!(error = %e, "database backup task failed"),
            }
        }
    });
}

/// Run one backup synchronously: integrity check, write to a temporary file,
/// rename into place, then prune old backups down to `keep`. Returns the path
/// of the new backup.
pub fn run_once(storage: &Storage, cfg: &BackupConfig) -> anyhow::Result<PathBuf> {
    storage
        .check()
        .context("integrity check failed; skipping backup and keeping existing backups")?;
    let dir = &cfg.dir;
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating backup directory {}", dir.display()))?;
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%S%.fZ");
    let final_path = dir.join(format!("{PREFIX}{stamp}{SUFFIX}"));
    let tmp_path = dir.join(format!(".{PREFIX}{stamp}{SUFFIX}.tmp"));
    let written = storage.backup_to(&tmp_path).and_then(|()| {
        std::fs::rename(&tmp_path, &final_path).with_context(|| {
            format!(
                "renaming {} to {}",
                tmp_path.display(),
                final_path.display()
            )
        })
    });
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }
    prune(dir, cfg.keep)?;
    Ok(final_path)
}

fn is_backup_name(name: &str) -> bool {
    name.starts_with(PREFIX) && name.ends_with(SUFFIX)
}

fn prune(dir: &Path, keep: usize) -> anyhow::Result<()> {
    let mut files = std::fs::read_dir(dir)
        .with_context(|| format!("listing backup directory {}", dir.display()))?
        .filter_map(|entry| entry.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(is_backup_name)
        })
        .collect::<Vec<_>>();
    files.sort();
    let remove = files.len().saturating_sub(keep);
    for old in files.into_iter().take(remove) {
        std::fs::remove_file(&old)
            .with_context(|| format!("removing old backup {}", old.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "rust-dns-backup-{tag}-{}-{nonce}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn setup(tag: &str, keep: usize) -> (TempDir, Storage, BackupConfig) {
        let tmp = TempDir::new(tag);
        let storage = Storage::open(&tmp.0.join("live.db")).unwrap();
        let cfg = BackupConfig {
            dir: tmp.0.join("backups"),
            interval_hours: 1,
            keep,
        };
        (tmp, storage, cfg)
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn run_once_produces_final_file_and_no_tmp() {
        let (_tmp, storage, cfg) = setup("final", 3);
        let path = run_once(&storage, &cfg).unwrap();
        assert!(path.is_file());
        let name = path.file_name().unwrap().to_str().unwrap();
        assert!(is_backup_name(name), "{name}");
        let files = names(&cfg.dir);
        assert_eq!(files, vec![name.to_string()]);
        assert!(files.iter().all(|n| !n.ends_with(".tmp")));
        let restored = Storage::open(&path).unwrap();
        restored.check().unwrap();
    }

    #[test]
    fn tmp_name_is_not_a_backup_name() {
        assert!(!is_backup_name(".rust-dns-20260101T000000Z.db.tmp"));
        assert!(is_backup_name("rust-dns-20260101T000000Z.db"));
    }

    #[test]
    fn run_once_prunes_to_keep_and_ignores_unrelated_files() {
        let (_tmp, storage, cfg) = setup("prune", 2);
        std::fs::create_dir_all(&cfg.dir).unwrap();
        for old in [
            "rust-dns-20000101T000000.000000Z.db",
            "rust-dns-20000102T000000.000000Z.db",
            "rust-dns-20000103T000000.000000Z.db",
        ] {
            std::fs::write(cfg.dir.join(old), b"old").unwrap();
        }
        let unrelated = ["notes.txt", "other.db", ".rust-dns-20000101T000000Z.db.tmp"];
        for f in unrelated {
            std::fs::write(cfg.dir.join(f), b"keep me").unwrap();
        }
        let newest = run_once(&storage, &cfg).unwrap();
        let newest_name = newest.file_name().unwrap().to_str().unwrap().to_string();
        let files = names(&cfg.dir);
        let backups: Vec<&String> = files.iter().filter(|n| is_backup_name(n)).collect();
        assert_eq!(
            backups,
            vec![
                &"rust-dns-20000103T000000.000000Z.db".to_string(),
                &newest_name
            ]
        );
        for f in unrelated {
            assert!(files.iter().any(|n| n == f), "{f} was removed");
        }
    }
}
