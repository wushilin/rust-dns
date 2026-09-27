//! Structured logging with size-based rotation, retention and gzip, plus a
//! separate query log and a runtime-reloadable level filter.

use crate::config::LoggingConfig;
use anyhow::{Context, Result};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, reload, EnvFilter, Layer, Registry};

/// Target used for per-query log lines so they can be routed to their own file.
pub const QUERY_TARGET: &str = "rust_dns::query";

type ReloadHandle = reload::Handle<EnvFilter, Registry>;
static LEVEL_HANDLE: OnceLock<ReloadHandle> = OnceLock::new();

/// Change the log level filter at runtime (used by config reload).
pub fn set_level(spec: &str) -> Result<()> {
    let filter = EnvFilter::try_new(spec).with_context(|| format!("invalid log level '{spec}'"))?;
    match LEVEL_HANDLE.get() {
        Some(h) => h.reload(filter).context("reloading log filter"),
        None => anyhow::bail!("logging not initialised"),
    }
}

// ---------------------------------------------------------------------------
// rotating file writer
// ---------------------------------------------------------------------------

struct Inner {
    path: PathBuf,
    file: File,
    size: u64,
}

pub struct RotatingFile {
    inner: Mutex<Inner>,
    max_size: u64,
    max_files: usize,
    compress: bool,
}

impl RotatingFile {
    pub fn open(path: &Path, max_size: u64, max_files: usize, compress: bool) -> Result<Arc<Self>> {
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)
                    .with_context(|| format!("creating log directory {}", dir.display()))?;
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("opening log file {}", path.display()))?;
        let size = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Arc::new(RotatingFile {
            inner: Mutex::new(Inner {
                path: path.to_path_buf(),
                file,
                size,
            }),
            max_size: max_size.max(64 * 1024),
            max_files: max_files.max(1),
            compress,
        }))
    }

    fn write_bytes(&self, buf: &[u8]) -> io::Result<()> {
        let mut g = self.inner.lock().unwrap();
        if g.size > 0 && g.size + buf.len() as u64 > self.max_size {
            self.rotate(&mut g)?;
        }
        g.file.write_all(buf)?;
        g.size += buf.len() as u64;
        Ok(())
    }

    fn rotate(&self, g: &mut Inner) -> io::Result<()> {
        let _ = g.file.flush();
        let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%S%.3fZ");
        let rotated = rotated_path(&g.path, &stamp.to_string());
        std::fs::rename(&g.path, &rotated)?;
        g.file = OpenOptions::new().create(true).append(true).open(&g.path)?;
        g.size = 0;
        let (compress, max_files, base) = (self.compress, self.max_files, g.path.clone());
        std::thread::spawn(move || {
            if compress {
                if let Err(e) = gzip_file(&rotated) {
                    eprintln!("rust-dns: compressing {} failed: {e}", rotated.display());
                }
            }
            prune(&base, max_files);
        });
        Ok(())
    }
}

fn rotated_path(base: &Path, stamp: &str) -> PathBuf {
    let name = base
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "log".into());
    base.with_file_name(format!("{name}.{stamp}"))
}

fn gzip_file(path: &Path) -> io::Result<()> {
    let gz_path = PathBuf::from(format!("{}.gz", path.display()));
    let mut input = File::open(path)?;
    let out = File::create(&gz_path)?;
    let mut enc = flate2::write::GzEncoder::new(out, flate2::Compression::default());
    io::copy(&mut input, &mut enc)?;
    enc.finish()?.sync_all()?;
    std::fs::remove_file(path)
}

/// Keep only the newest `keep` rotated files for `base` (timestamped names sort chronologically).
fn prune(base: &Path, keep: usize) {
    let Some(dir) = base.parent() else { return };
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    let Some(name) = base.file_name().map(|n| n.to_string_lossy().into_owned()) else {
        return;
    };
    let prefix = format!("{name}.");
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut rotated: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .map(|f| f.to_string_lossy().starts_with(&prefix))
                .unwrap_or(false)
        })
        .collect();
    rotated.sort();
    while rotated.len() > keep {
        let old = rotated.remove(0);
        let _ = std::fs::remove_file(old);
    }
}

/// Cloneable `Write` handle for `tracing_subscriber`'s `MakeWriter`.
#[derive(Clone)]
pub struct Handle(Arc<RotatingFile>);

impl Write for Handle {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write_bytes(buf)?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.inner.lock().unwrap().file.flush()
    }
}

// ---------------------------------------------------------------------------
// subscriber setup
// ---------------------------------------------------------------------------

fn open_writer(cfg: &LoggingConfig, path: &str) -> Result<Handle> {
    Ok(Handle(RotatingFile::open(
        Path::new(path),
        cfg.max_size_mb * 1024 * 1024,
        cfg.max_files,
        cfg.compress,
    )?))
}

type BoxedLayer = Box<dyn Layer<Registry> + Send + Sync>;

fn fmt_layer(cfg: &LoggingConfig, writer: Option<Handle>) -> BoxedLayer {
    let json = cfg.format.eq_ignore_ascii_case("json");
    match (writer, json) {
        (Some(w), true) => fmt::layer()
            .with_writer(move || w.clone())
            .json()
            .flatten_event(true)
            .with_current_span(false)
            .boxed(),
        (Some(w), false) => fmt::layer()
            .with_writer(move || w.clone())
            .with_ansi(false) // plain text in log files
            .with_target(false)
            .boxed(),
        (None, true) => fmt::layer()
            .with_writer(io::stdout)
            .json()
            .flatten_event(true)
            .with_current_span(false)
            .boxed(),
        (None, false) => fmt::layer()
            .with_writer(io::stdout)
            // Colors only on a terminal, never into journald or a pipe.
            .with_ansi(std::io::IsTerminal::is_terminal(&io::stdout()))
            .with_target(false)
            .boxed(),
    }
}

pub fn init(cfg: &LoggingConfig) -> Result<()> {
    let level = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(cfg.level.clone()))
        .with_context(|| format!("invalid [logging].level '{}'", cfg.level))?;
    let (level_layer, handle) = reload::Layer::new(level);
    let _ = LEVEL_HANDLE.set(handle);

    let separate_queries = !cfg.query_log_file.is_empty();
    let main_writer = if cfg.file.is_empty() {
        None
    } else {
        Some(open_writer(cfg, &cfg.file)?)
    };
    // Main log: everything except query lines when those have their own file.
    let main = fmt_layer(cfg, main_writer).with_filter(filter_fn(move |m| {
        !(separate_queries && m.target() == QUERY_TARGET)
    }));

    let mut layers: Vec<BoxedLayer> = vec![Box::new(level_layer), Box::new(main)];
    if separate_queries {
        let q = fmt_layer(cfg, Some(open_writer(cfg, &cfg.query_log_file)?))
            .with_filter(filter_fn(|m| m.target() == QUERY_TARGET));
        layers.push(Box::new(q));
    }
    tracing_subscriber::registry()
        .with(layers)
        .try_init()
        .context("initialising logging")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotates_compresses_and_prunes() {
        let dir = std::env::temp_dir().join(format!("rust-dns-log-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let base = dir.join("app.log");
        let rf = RotatingFile::open(&base, 64 * 1024, 3, true).unwrap();
        let line = vec![b'x'; 1000];
        for _ in 0..400 {
            // 400 KB total -> at least 5 rotations, keep 3
            rf.write_bytes(&line).unwrap();
            rf.write_bytes(b"\n").unwrap();
        }
        // Give the background gzip/prune threads a moment.
        std::thread::sleep(std::time::Duration::from_millis(800));
        let names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        let rotated: Vec<&String> = names.iter().filter(|n| n.starts_with("app.log.")).collect();
        assert!(rotated.len() <= 3, "pruned to max_files: {rotated:?}");
        assert!(!rotated.is_empty());
        assert!(
            rotated.iter().all(|n| n.ends_with(".gz")),
            "rotated files are gzipped: {rotated:?}"
        );
        assert!(std::fs::metadata(&base).unwrap().len() <= 64 * 1024 + 1001);
        // gz content is readable
        let gz = dir.join(rotated[0]);
        let mut dec = flate2::read::GzDecoder::new(File::open(gz).unwrap());
        let mut s = String::new();
        std::io::Read::read_to_string(&mut dec, &mut s).unwrap();
        assert!(s.starts_with("xxxx"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
