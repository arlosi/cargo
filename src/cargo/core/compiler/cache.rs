//! Implements a cache for compilation artifacts.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use bincode;
use serde::{Serialize, Deserialize};

use crate::core::PackageId;

use super::context::OutputFile;
use super::fingerprint::Fingerprint;

pub trait Cache: Send + Sync {
    // TODO How to handle "uncachable" crates, or crates that depend on those.

    /// Try to get an item from the cache by its Fingerprint and place it in the target_root.
    /// If the cache is hit, the paths of files placed in the target_root are returned.
    fn get(
        &self,
        package_id: &PackageId,
        fingerprint: &Fingerprint,
    ) -> bool;
    fn put(&self, package_id: &PackageId, fingerprint: &Fingerprint, outputs: &[OutputFile]);
}

pub fn create_cache() -> Arc<dyn Cache> {
    Arc::new(LocalCache {
        cache_directory: home::cargo_home().unwrap().join(CACHE_SUBDIRECTORY),
    })
}

/// Current cache version.
const CACHE_VERSION: u64 = 2;

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
    #[serde(flatten)]
    package_common: &'a PackageKey<'a>,
}

impl<'a> Key<'a> {
    fn new(package_common: &'a PackageKey<'a>) -> Self {
        Self {
            cache_version: CACHE_VERSION,
            package_common,
        }
    }
}

/// A serializable version of an OutputFile.
#[derive(Debug, Serialize, Deserialize)]
struct SerializableOutputFile {
    pub path: PathBuf,
    pub file_data: Vec<u8>,
}

impl From<&OutputFile> for SerializableOutputFile { // TODO: Result: should be TryFrom
    fn from(value: &OutputFile) -> Self {
        SerializableOutputFile { path: value.path.clone(), file_data: fs::read(&value.path).unwrap() } // TODO: Result
    }
}

/// A group of OutputFiles in a form that can be serialized and deserialized.
#[derive(Serialize, Deserialize)]
struct SerializableOutputFiles {
    pub outputs: Vec<SerializableOutputFile>,
}

impl Cache for LocalCache {
    fn get(
        &self,
        package_id: &PackageId,
        fingerprint: &Fingerprint,
    ) -> bool {
        if !package_id.source_id().is_remote_registry() {
            tracing::debug!("GET: Unsupported registry for '{package_id:?}'");
            return false;
        }
        let package_common_key = PackageKey::new(package_id.clone(), fingerprint);
        let key = serde_json::to_string(&Key::new(&package_common_key)).unwrap();

        let cache_value = cacache::read_sync(&self.cache_directory, &key);
        if let Ok(cache_value) = cache_value {
            let cache_value = bincode::deserialize::<SerializableOutputFiles>(&cache_value).unwrap(); // TODO: Result

            for serialized_output in cache_value.outputs {
                let path = &serialized_output.path;
                fs::write(path, &serialized_output.file_data).unwrap();
                tracing::debug!(
                    "GET: Writing cached output file '{path:?}' for '{package_id:?}'"
                );
            }

            true
        } else {
            tracing::debug!("GET: Could not get entry for '{package_id:?}'");

            false
        }
    }

    fn put(&self, package_id: &PackageId, fingerprint: &Fingerprint, outputs: &[OutputFile]) {
        if !package_id.source_id().is_remote_registry() {
            tracing::debug!("PUT: Unsupported registry for '{package_id:?}'");
            return;
        }

        let package_common_key = PackageKey::new(package_id.clone(), fingerprint);
        let key = serde_json::to_string(&Key::new(&package_common_key)).unwrap();
        let files = SerializableOutputFiles { outputs: outputs.iter().map(SerializableOutputFile::from).collect() };
        let serialized_files = bincode::serialize(&files).unwrap();

        match cacache::metadata_sync(&self.cache_directory, &key) {
            Ok(Some(metadata))
                if cacache::exists_sync(&self.cache_directory, &metadata.integrity) =>
            {
                // Entry exists and has data, nothing to do.
                tracing::debug!(
                    "PUT: Found '{package_id:?}' in cache, skipping update"
                );
            }
            _ => {
                tracing::debug!("PUT: Adding '{package_id:?}' to cache");
                if let Err(err) = (|| -> anyhow::Result<()> {
                    cacache::write_sync(&self.cache_directory, &key, &serialized_files).unwrap(); // TODO: Result
                    Ok(())
                })() {
                    // TODO DO we need better error handling, or is this ok?
                    tracing::warn!(
                        "Failed to add '{package_id:?}' to cache: {err:?}"
                    );
                }
            }
        }
    }
}
