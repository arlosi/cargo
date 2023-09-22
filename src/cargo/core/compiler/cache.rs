//! Implements a cache for compilation artifacts.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::core::{PackageId, TargetKind};
use crate::CargoResult;
use crate::util::config::SharedUserCacheConfig;

use super::context::OutputFile;
use super::fingerprint::Fingerprint;

pub trait Cache: Send + Sync {
    /// Try to get an item from the cache by its Fingerprint and place it in the target_root.
    /// If the cache is hit, the paths of files placed in the target_root are returned.
    fn get(
        &self,
        package_id: &PackageId,
        fingerprint: &Fingerprint,
        target_kind: &TargetKind,
        all_deps: &[(PackageId, TargetKind)],
        outputs: &[OutputFile],
    ) -> CargoResult<bool>;
    fn put(
        &self,
        package_id: &PackageId,
        fingerprint: &Fingerprint,
        target_kind: &TargetKind,
        all_deps: &[(PackageId, TargetKind)],
        outputs: &[OutputFile],
    ) -> CargoResult<()>;
}

pub fn create_cache(shared_user_cache_config: &SharedUserCacheConfig) -> Arc<dyn Cache> {
    Arc::new(LocalCache {
        cache_directory: home::cargo_home().unwrap().join(&shared_user_cache_config.path),
    })
}

/// Current cache version.
const CACHE_VERSION: u64 = 1;

const ALLOWED_RUST_FLAGS: [&'static str; 3] = [
    "-C",
    "-Ctarget-feature=+crt-static",
    "target-feature=+crt-static",
];

struct LocalCache {
    cache_directory: PathBuf,
}

// TODO Figure out the correct key to use here.

/// Key to find a unique artifact in the cache.
#[derive(Debug, Serialize)]
struct Key<'a> {
    /// Version, in case the meaning of any field changes.
    cache_version: u64,

    // Information for the Key taken from [`Fingerprint`].
    rustc: u64,
    features: &'a str,
    target: u64,
    profile: u64,
    config: u64,
    rustflags: &'a [String],

    package_id: PackageId,

    target_kind: &'a TargetKind,
}

impl<'a> Key<'a> {
    fn new(
        package_id: PackageId,
        fingerprint: &'a Fingerprint,
        target_kind: &'a TargetKind,
    ) -> Self {
        Self {
            cache_version: CACHE_VERSION,
            rustc: fingerprint.rustc,
            features: &fingerprint.features,
            target: fingerprint.target,
            profile: fingerprint.profile,
            config: fingerprint.config,
            rustflags: &fingerprint.rustflags,
            package_id,
            target_kind,
        }
    }
}

/// Structure that serialized per-cache key with pointers
/// to other cache entries for individual files.
#[derive(Serialize, Deserialize)]
struct CacheMetadata {
    files: HashMap<String, cacache::Integrity>,
}

impl LocalCache {
    fn is_cachable(
        package_id: &PackageId,
        fingerprint: Option<&Fingerprint>,
        target_kind: &TargetKind,
        all_deps: Option<&[(PackageId, TargetKind)]>,
    ) -> bool {
        // TODO what else makes something uncachable?

        if !package_id.source_id().is_remote_registry() {
            tracing::debug!(
                "'{package_id}' (as {target_kind:?}) is uncachable: unsupported registry"
            );
            return false;
        }

        if matches!(fingerprint, Some(fingerprint) if fingerprint.rustflags.iter().any(|f| !ALLOWED_RUST_FLAGS.iter().contains(&f.as_str())))
        {
            tracing::debug!("'{package_id}' (as {target_kind:?}) is uncachable: RUSTFLAGS is set");
            return false;
        }

        if let Some(all_deps) = all_deps {
            if all_deps
                .iter()
                .any(|(_, tk)| matches!(tk, TargetKind::CustomBuild))
            {
                tracing::debug!(
                    "'{package_id}' (as {target_kind:?}) is uncachable: depends on build script"
                );
                return false;
            }
            if all_deps
                .iter()
                .any(|(_, tk)|
                    matches!(tk, TargetKind::Lib(types) if types.contains(&super::CrateType::ProcMacro))
                )
            {
                tracing::debug!(
                    "'{package_id}' (as {target_kind:?}) is uncachable: depends on a proc macro"
                );
                return false;
            }

            if !all_deps
                .iter()
                .all(|(p, tk)| LocalCache::is_cachable(p, None, tk, None))
            {
                tracing::debug!(
                    "'{package_id}' (as {target_kind:?}) is uncachable: dependency is uncachable"
                );
                return false;
            }
        }

        true
    }
}

impl Cache for LocalCache {
    fn get(
        &self,
        package_id: &PackageId,
        fingerprint: &Fingerprint,
        target_kind: &TargetKind,
        all_deps: &[(PackageId, TargetKind)],
        outputs: &[OutputFile],
    ) -> CargoResult<bool> {
        if !LocalCache::is_cachable(package_id, Some(fingerprint), target_kind, Some(all_deps)) {
            return Ok(false);
        }

        let mut all_found = true;
        let key =
            serde_json::to_string(&Key::new(package_id.clone(), fingerprint, target_kind)).unwrap();
        let Some(metadata) = cacache::metadata_sync(&self.cache_directory, &key)? else {
            return Ok(false);
        };
        let metadata: CacheMetadata = serde_json::from_value(metadata.metadata)?;
        for output in outputs {
            if let Some(sri) = metadata
                .files
                .get(output.path.file_name().unwrap().to_str().unwrap())
            {
                // TODO Try to hardlink, fallback to copy (reflink is only supported for ReFS).
                fs::create_dir_all(output.path.parent().unwrap())?;
                match cacache::copy_hash_sync(&self.cache_directory, sri, &output.path) {
                    Ok(_) => {
                        tracing::debug!(
                            "GET: Found {flavor:?} for '{package_id}' (as {target_kind:?}) in cache, copying to {path:?}",
                            flavor=output.flavor,
                            path=output.path,
                        );
                    }
                    Err(cacache::Error::EntryNotFound(..)) => {
                        tracing::debug!(
                            "GET: Did not find {flavor:?} for '{package_id}' (as {target_kind:?}) in cache",
                            flavor=output.flavor
                        );
                        all_found = false;
                    }
                    Err(err) => {
                        tracing::debug!(
                            "GET: Error retrieving {flavor:?} for '{package_id}' (as {target_kind:?}): {err:?}",
                            flavor=output.flavor
                        );
                        return Err(err.into());
                    }
                }
            }
        }
        Ok(all_found)
    }

    fn put(
        &self,
        package_id: &PackageId,
        fingerprint: &Fingerprint,
        target_kind: &TargetKind,
        all_deps: &[(PackageId, TargetKind)],
        outputs: &[OutputFile],
    ) -> CargoResult<()> {
        if !LocalCache::is_cachable(package_id, Some(fingerprint), target_kind, Some(all_deps)) {
            return Ok(());
        }

        let key =
            serde_json::to_string(&Key::new(package_id.clone(), fingerprint, target_kind)).unwrap();
        let previous_metadata = cacache::metadata_sync(&self.cache_directory, &key);
        match previous_metadata {
            Ok(Some(metadata))
                if cacache::exists_sync(&self.cache_directory, &metadata.integrity) =>
            {
                for output in outputs {
                    // Entry exists and has data, nothing to do.
                    tracing::debug!(
                        "PUT: Found {flavor:?} for '{package_id}' (as {target_kind:?}) in cache, skipping update",
                        flavor=output.flavor
                    );
                }
                return Ok(());
            }
            _ => {}
        }

        let mut metadata = CacheMetadata {
            files: HashMap::new(),
        };

        for output in outputs {
            tracing::debug!(
                "PUT: Adding {flavor:?} for '{package_id}' (as {target_kind:?}) to cache",
                flavor = output.flavor
            );
            let mut writer = cacache::WriteOpts::new().open_hash_sync(&self.cache_directory)?;
            io::copy(
                &mut File::open(&output.path).context("open build output")?,
                &mut writer,
            )
            .context("copy build output to cache")?;

            let integrity = writer.commit().context("Commit data to cache")?;
            metadata.files.insert(
                output
                    .path
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string(),
                integrity,
            );
        }

        // We don't get an error if racing to add to the cache. Both entries are added, but the key will point to the newest one.
        cacache::WriteOpts::new()
            .metadata(serde_json::to_value(&metadata).unwrap())
            .open_sync(&self.cache_directory, &key)?
            .commit()?;
        Ok(())
    }
}
