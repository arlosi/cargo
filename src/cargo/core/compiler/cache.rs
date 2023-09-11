//! Implements a cache for compilation artifacts.

use std::{path::PathBuf, sync::Arc};

use crate::core::PackageId;

use super::FileFlavor;

pub trait Cache: Send + Sync {
    // TODO Figure out the correct key to use here.
    // TODO How to handle "uncachable" crates, or crates that depend on those.
    fn get(&self, package_id: PackageId, file_flavor: &FileFlavor, output: &PathBuf) -> bool;
    fn put(&self, package_id: PackageId, file_flavor: &FileFlavor, item: &PathBuf);
}

pub fn create_cache() -> Arc<dyn Cache> {
    Arc::new(LocalCache {})
}

struct LocalCache {}

impl Cache for LocalCache {
    fn get(&self, _package_id: PackageId, file_flavor: &FileFlavor, output: &PathBuf) -> bool {
        tracing::debug!("Get {file_flavor:?} {output:?}");
        false
    }

    fn put(&self, _package_id: PackageId, file_flavor: &FileFlavor, item: &PathBuf) {
        tracing::debug!("Put {file_flavor:?} {item:?}");
    }
}
