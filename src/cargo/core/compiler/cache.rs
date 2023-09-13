//! Implements a cache for compilation artifacts.

use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use serde::Serialize;

use crate::core::PackageId;

use super::context::OutputFile;
use super::fingerprint::Fingerprint;
use super::FileFlavor;

pub trait Cache: Send + Sync {
    // TODO How to handle "uncachable" crates, or crates that depend on those.

    /// Try to get an item from the cache by its Fingerprint and place it in the target_root.
    /// If the cache is hit, the paths of files placed in the target_root are returned.
    fn get(
        &self,
        package_id: &PackageId,
        fingerprint: &Fingerprint,
        outputs: &[OutputFile],
    ) -> bool;
    fn put(&self, package_id: &PackageId, fingerprint: &Fingerprint, outputs: &[OutputFile]);
}

pub fn create_cache() -> Arc<dyn Cache> {
    Arc::new(LocalCache {
        cache_directory: home::cargo_home().unwrap().join(CACHE_SUBDIRECTORY),
    })
}

/// Current cache version.
const CACHE_VERSION: u64 = 1;

/// Default sub-directory for the cache.
const CACHE_SUBDIRECTORY: &'static str = "artifact_cache";

struct LocalCache {
    cache_directory: PathBuf,
}

/// Key information that is common across all items in a package.
#[derive(Debug, Serialize)]
struct PackageKey<'a> {
    // Information for the Key taken from [`Fingerprint`].
    rustc: u64,
    features: &'a str,
    target: u64,
    profile: u64,
    config: u64,

    package_id: PackageId,
}

impl<'a> PackageKey<'a> {
    fn new(package_id: PackageId, fingerprint: &'a Fingerprint) -> Self {
        Self {
            rustc: fingerprint.rustc,
            features: &fingerprint.features,
            target: fingerprint.target,
            profile: fingerprint.profile,
            config: fingerprint.config,
            package_id,
        }
    }
}

// TODO Figure out the correct key to use here.
#[derive(Debug, Serialize)]
struct Key<'a> {
    /// Version, in case the meaning of any field changes.
    cache_version: u64,
    // TODO is this unique per file in a crate?
    file_flavor: FileFlavor,
    #[serde(flatten)]
    package_common: &'a PackageKey<'a>,
}

impl<'a> Key<'a> {
    fn new(file_flavor: FileFlavor, package_common: &'a PackageKey<'a>) -> Self {
        Self {
            cache_version: CACHE_VERSION,
            file_flavor,
            package_common,
        }
    }
}

impl LocalCache {
    fn is_cachable(package_id: &PackageId) -> bool {
        if !package_id.source_id().is_remote_registry() {
            tracing::debug!("'{package_id:?}' is uncachable: unsupported registry");
            return false;
        }

        true
    }
}

impl Cache for LocalCache {
    fn get(
        &self,
        package_id: &PackageId,
        fingerprint: &Fingerprint,
        outputs: &[OutputFile],
    ) -> bool {
        if !LocalCache::is_cachable(package_id) {
            return false;
        }

        let mut all_found = true;
        let package_common_key = PackageKey::new(package_id.clone(), fingerprint);
        for output in outputs {
            let key = serde_json::to_string(&Key::new(output.flavor, &package_common_key)).unwrap();
            // TODO Try to hardlink, fallback to copy (reflink is only supported for ReFS).
            // TODO What if the file already exists? Skip or overwrite?
            if cacache::copy_sync(&self.cache_directory, &key, &output.path).is_ok() {
                tracing::debug!(
                    "GET: Found '{output:?}' for '{package_id:?}' in cache, copying to target dir"
                );
            } else {
                tracing::debug!("GET: Did not find '{output:?}' for '{package_id:?}' in cache");
                all_found = false;
            }
        }

        all_found
    }

    fn put(&self, package_id: &PackageId, fingerprint: &Fingerprint, outputs: &[OutputFile]) {
        if !LocalCache::is_cachable(package_id) {
            return;
        }

        let package_common_key = PackageKey::new(package_id.clone(), fingerprint);
        for output in outputs {
            let key = serde_json::to_string(&Key::new(output.flavor, &package_common_key)).unwrap();
            match cacache::metadata_sync(&self.cache_directory, &key) {
                Ok(Some(metadata))
                    if cacache::exists_sync(&self.cache_directory, &metadata.integrity) =>
                {
                    // Entry exists and has data, nothing to do.
                    tracing::debug!(
                        "PUT: Found '{output:?}' for '{package_id:?}' in cache, skipping update"
                    );
                }
                _ => {
                    tracing::debug!("PUT: Adding '{output:?}' for '{package_id:?}' to cache");
                    if let Err(err) = (|| -> anyhow::Result<()> {
                        let mut writer = cacache::SyncWriter::create(&self.cache_directory, &key)
                            .context("Create cache writer")?;
                        io::copy(
                            &mut File::open(&output.path).context("Open build output")?,
                            &mut writer,
                        )
                        .context("Copy build output to cache")?;
                        // TODO What error would we get if we were racing to write this item?
                        writer.commit().context("Commit data to cache")?;
                        Ok(())
                    })() {
                        // TODO DO we need better error handling, or is this ok?
                        tracing::warn!(
                            "Failed to add '{output:?}' for '{package_id:?}' to cache: {err:?}"
                        );
                    }
                }
            }
        }
    }
}
