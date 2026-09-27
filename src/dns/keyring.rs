//! In-memory TSIG keys for the DNS hot path (which never reads SQLite).
//! Rebuilt from the `tsig_keys` table at startup and after every change.

use super::tsig::{Algorithm, Key};
use crate::storage::{Storage, StoredTsigKey};
use std::collections::HashMap;
use std::sync::Arc;

pub struct KeyEntry {
    pub key: Key,
    /// Zones this key may transfer; empty = all zones.
    pub zones: Vec<String>,
}

impl KeyEntry {
    /// `zone` as stored (`example.com`, no trailing dot).
    pub fn allows_zone(&self, zone: &str) -> bool {
        self.zones.is_empty() || self.zones.iter().any(|z| z.eq_ignore_ascii_case(zone))
    }
}

#[derive(Default)]
pub struct Keyring {
    keys: HashMap<String, Arc<KeyEntry>>,
}

impl Keyring {
    pub fn from_stored(rows: Vec<StoredTsigKey>) -> Self {
        let mut keys = HashMap::new();
        for r in rows {
            let Some(algorithm) = Algorithm::from_name(&r.algorithm) else {
                tracing::warn!(key = %r.name, algorithm = %r.algorithm, "ignoring TSIG key with an unsupported algorithm");
                continue;
            };
            keys.insert(
                r.name.to_ascii_lowercase(),
                Arc::new(KeyEntry {
                    key: Key {
                        name: r.name.to_ascii_lowercase(),
                        algorithm,
                        secret: r.secret,
                    },
                    zones: r.zones,
                }),
            );
        }
        Keyring { keys }
    }

    pub fn load(storage: &Storage) -> anyhow::Result<Self> {
        Ok(Self::from_stored(storage.list_tsig_keys()?))
    }

    /// Look up by key name (any case, with or without the trailing dot).
    pub fn get(&self, name: &str) -> Option<&Arc<KeyEntry>> {
        let mut n = name.to_ascii_lowercase();
        if !n.ends_with('.') {
            n.push('.');
        }
        self.keys.get(&n)
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}
