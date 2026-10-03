//! The write gate: closed on a standby (and on a fenced old primary).

/// Whether this server accepts writes. Closed on a standby (and on a fenced
/// old primary): [`Mutator::execute`](super::Mutator::execute) refuses every DNS operation, so no
/// background writer (the expiry sweeper) or forgotten route can write. The
/// replication apply path (`replica`) is the only DNS writer then.
pub struct WriteGate {
    read_only: std::sync::atomic::AtomicBool,
    reason: std::sync::RwLock<String>,
}

impl Default for WriteGate {
    fn default() -> Self {
        WriteGate {
            read_only: std::sync::atomic::AtomicBool::new(false),
            reason: std::sync::RwLock::new(String::new()),
        }
    }
}

impl WriteGate {
    pub fn read_only(&self) -> bool {
        self.read_only.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The message given to refused writers.
    pub fn reason(&self) -> String {
        self.reason
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    pub fn close(&self, reason: impl Into<String>) {
        *self.reason.write().unwrap_or_else(|p| p.into_inner()) = reason.into();
        self.read_only
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn open(&self) {
        self.read_only
            .store(false, std::sync::atomic::Ordering::SeqCst);
        self.reason
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
    }
}
