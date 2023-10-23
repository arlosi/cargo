//! Implements a cache for compilation artifacts.

use std::fs::{self};
use std::hash::Hash;
use std::path::PathBuf;
use std::sync::Arc;

use itertools::Itertools;

use crate::core::{PackageId, TargetKind};
use crate::util::config::SharedUserCacheConfig;
use crate::CargoResult;
use crate::util::short_hash;

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
    let mut path = PathBuf::new();
    path.push(&shared_user_cache_config.path);
    let path = if path.is_absolute() {
        path
    } else {
        home::cargo_home().unwrap().join(&path)
    };
    Arc::new(LocalCache {
        cache_directory: path,
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
#[derive(Debug, Hash)]
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

    fn tmp(&self) -> CargoResult<PathBuf> {
        let path = self.cache_directory.join("tmp");
        std::fs::create_dir_all(&path)?;
        Ok(path)
    }

    fn path(&self, key: &Key<'_>) -> PathBuf {
        let sid = key.package_id.source_id();
        let sid_hash = short_hash(&sid);
        let full_hash = short_hash(&key);
        let mut path = self.cache_directory.clone();
        path.push(format!("{}-{}", sid.url().host_str().unwrap_or_default(), sid_hash));
        path.push(key.package_id.name());
        path.push(key.package_id.version().to_string());
        path.push(full_hash);
        path
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
        let key = self.path(&Key::new(package_id.clone(), fingerprint, target_kind));
        if !key.exists() {
            return Ok(false);
        };
        for output in outputs {
            let cache_path = key.join(output.path.file_name().unwrap());
            fs::create_dir_all(output.path.parent().unwrap())?;

            match fs::copy(&cache_path, &output.path) {
                Ok(_) => {
                    tracing::debug!(
                        "GET: Found {flavor:?} for '{package_id}' (as {target_kind:?}) in cache, copying to {path:?}",
                        flavor=output.flavor,
                        path=output.path,
                    );
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
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

        let key = self.path(&Key::new(package_id.clone(), fingerprint, target_kind));
        tracing::debug!(key=key.to_str());
        if key.exists() {
            for output in outputs {
                // Entry exists and has data, nothing to do.
                tracing::debug!(
                    "PUT: Found {flavor:?} for '{package_id}' (as {target_kind:?}) in cache, skipping update",
                    flavor=output.flavor
                );
            }
            return Ok(());
        }

        let tmp = self.tmp()?;
        for output in outputs {
            tracing::debug!(
                "PUT: Adding {flavor:?} for '{package_id}' (as {target_kind:?}) to cache",
                flavor = output.flavor
            );
            fs::copy(&output.path, tmp.join(output.path.file_name().unwrap()))?;
        }
        match fs::rename(&tmp, &key) {
            Ok(()) => Ok(()),
            Err(err) => {
                tracing::warn!("failed renaming cache entry: {err}");
                let _ = fs::remove_dir_all(&tmp);
                Ok(())
            },
        }
    }
}
