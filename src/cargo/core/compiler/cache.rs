//! Implements a cache for compilation artifacts.

use std::{path::Path, sync::Arc};

use super::fingerprint::Fingerprint;

pub trait Cache: Send + Sync {
    // TODO Figure out the correct key to use here.
    // TODO How to handle "uncachable" crates, or crates that depend on those.
    fn get(&self, fingerprint: &Fingerprint, target_root: &Path) -> bool;
    fn put(&self, fingerprint: &Fingerprint, target_root: &Path);
}

pub fn create_cache() -> Arc<dyn Cache> {
    Arc::new(LocalCache {})
}

struct LocalCache {}

impl Cache for LocalCache {
    fn get(&self, _fingerprint: &Fingerprint, _target_root: &Path) -> bool {
        tracing::debug!("Get");
        false
    }

    fn put(&self, _fingerprint: &Fingerprint, _target_root: &Path) {
        tracing::debug!("Put");
    }
}
