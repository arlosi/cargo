//! Implements a cache for compilation artifacts.

use std::{path::{Path, PathBuf}, sync::Arc};

use super::fingerprint::Fingerprint;

pub trait Cache: Send + Sync {
    // TODO Figure out the correct key to use here.
    // TODO How to handle "uncachable" crates, or crates that depend on those.

    /// Try to get an item from the cache by its Fingerprint and place it in the target_root.
    /// If the cache is hit, the paths of files placed in the target_root are returned.
    fn get(&self, fingerprint: &Fingerprint, target_root: &Path) -> Option<Vec<PathBuf>>;
    fn put(&self, fingerprint: &Fingerprint, target_root: &Path);
}

pub fn create_cache() -> Arc<dyn Cache> {
    Arc::new(LocalCache {})
}

struct LocalCache {}

impl Cache for LocalCache {
    fn get(&self, _fingerprint: &Fingerprint, _target_root: &Path) -> Option<Vec<PathBuf>> {
        tracing::debug!("Get");
        None
    }

    fn put(&self, _fingerprint: &Fingerprint, _target_root: &Path) {
        tracing::debug!("Put");
    }
}
