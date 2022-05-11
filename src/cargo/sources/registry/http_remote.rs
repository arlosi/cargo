//! Access to a HTTP-based crate registry.
//!
//! See [`HttpRegistry`] for details.

use crate::core::{PackageId, SourceId};
use crate::ops::{self};
use crate::sources::registry::download;
use crate::sources::registry::MaybeLock;
use crate::sources::registry::{LoadResponse, RegistryConfig, RegistryData};
use crate::util::errors::CargoResult;
use crate::util::{
    auth, truncate_with_ellipsis, Config, Filesystem, IntoUrl, Progress, ProgressStyle,
};
use anyhow::Context;
use cargo_util::paths;
use curl::easy::{HttpVersion, List};
use curl::multi::{EasyHandle, Multi};
use log::{debug, trace};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::str;
use std::task::Poll;
use std::time::Duration;
use url::Url;

// HTTP headers
const ETAG: &'static str = "etag";
const LAST_MODIFIED: &'static str = "last-modified";
const WWW_AUTHENTICATE: &'static str = "www-authenticate";
const IF_NONE_MATCH: &'static str = "if-none-match";
const IF_MODIFIED_SINCE: &'static str = "if-modified-since";

const UNKNOWN: &'static str = "Unknown";

/// A registry served by the HTTP-based registry API.
///
/// This type is primarily accessed through the [`RegistryData`] trait.
///
/// `HttpRegistry` implements the HTTP-based registry API outlined in [RFC 2789]. Read the RFC for
/// the complete protocol, but _roughly_ the implementation loads each index file (e.g.,
/// config.json or re/ge/regex) from an HTTP service rather than from a locally cloned git
/// repository. The remote service can more or less be a static file server that simply serves the
/// contents of the origin git repository.
///
/// Implemented naively, this leads to a significant amount of network traffic, as a lookup of any
/// index file would need to check with the remote backend if the index file has changed. This
/// cost is somewhat mitigated by the use of HTTP conditional fetches (`If-Modified-Since` and
/// `If-None-Match` for `ETag`s) which can be efficiently handled by HTTP/2.
///
/// [RFC 2789]: https://github.com/rust-lang/rfcs/pull/2789
pub struct HttpRegistry<'cfg> {
    index_path: Filesystem,
    cache_path: Filesystem,
    source_id: SourceId,
    config: &'cfg Config,

    /// Store the server URL without the protocol prefix (sparse+)
    url: Url,

    /// HTTP multi-handle for asynchronous/parallel requests.
    multi: Multi,

    /// Has the client requested a cache update?
    ///
    /// Only if they have do we double-check the freshness of each locally-stored index file.
    requested_update: bool,

    /// State for currently pending index downloads.
    downloads: Downloads<'cfg>,

    /// Does the config say that we can use HTTP multiplexing?
    multiplexing: bool,

    /// What paths have we already fetched since the last index update?
    ///
    /// We do not need to double-check any of these index files since we have already done so.
    fresh: HashSet<PathBuf>,

    /// Have we started to download any index files?
    fetch_started: bool,

    /// Cached registry configuration.
    registry_config: Option<RegistryConfig>,

    /// Should we include the authorization header?
    auth_required: bool,

    /// Url to get a token for the registry.
    login_url: Option<Url>,
}

/// Helper for downloading crates.
pub struct Downloads<'cfg> {
    /// When a download is started, it is added to this map. The key is a
    /// "token" (see `Download::token`). It is removed once the download is
    /// finished.
    pending: HashMap<usize, (Download, EasyHandle)>,
    /// Set of paths currently being downloaded, mapped to their tokens.
    /// This should stay in sync with `pending`.
    pending_ids: HashMap<PathBuf, usize>,
    /// The final result of each download. A pair `(token, result)`. This is a
    /// temporary holding area, needed because curl can report multiple
    /// downloads at once, but the main loop (`wait`) is written to only
    /// handle one at a time.
    results: HashMap<PathBuf, Result<CompletedDownload, curl::Error>>,
    /// The next ID to use for creating a token (see `Download::token`).
    next: usize,
    /// Progress bar.
    progress: RefCell<Option<Progress<'cfg>>>,
    /// Number of downloads that have successfully finished.
    downloads_finished: usize,
}

struct Download {
    /// The token for this download, used as the key of the `Downloads::pending` map
    /// and stored in `EasyHandle` as well.
    token: usize,

    /// The path of the package that we're downloading.
    path: PathBuf,

    /// Actual downloaded data, updated throughout the lifetime of this download.
    data: RefCell<Vec<u8>>,

    /// HTTP headers.
    header_map: RefCell<Headers>,

    /// Statistics updated from the progress callback in libcurl.
    total: Cell<u64>,
    current: Cell<u64>,
}

#[derive(Default)]
struct Headers {
    last_modified: Option<String>,
    etag: Option<String>,
    www_authenticate: Vec<String>,
}

struct CompletedDownload {
    response_code: u32,
    data: Vec<u8>,
    header_map: Headers,
}

impl<'cfg> HttpRegistry<'cfg> {
    pub fn new(
        source_id: SourceId,
        config: &'cfg Config,
        name: &str,
    ) -> CargoResult<HttpRegistry<'cfg>> {
        if !config.cli_unstable().http_registry {
            anyhow::bail!("usage of HTTP-based registries requires `-Z http-registry`");
        }
        let url = source_id.url().as_str();
        // Ensure the url ends with a slash so we can concatinate paths.
        if !url.ends_with('/') {
            anyhow::bail!("registry url must end in a slash `/`: {url}")
        }
        let url = url
            .trim_start_matches("sparse+")
            .into_url()
            .expect("a url with the protocol stripped should still be valid");

        Ok(HttpRegistry {
            index_path: config.registry_index_path().join(name),
            cache_path: config.registry_cache_path().join(name),
            source_id,
            config,
            url,
            multi: Multi::new(),
            multiplexing: false,
            downloads: Downloads {
                next: 0,
                pending: HashMap::new(),
                pending_ids: HashMap::new(),
                results: HashMap::new(),
                progress: RefCell::new(Some(Progress::with_style(
                    "Fetch",
                    ProgressStyle::Ratio,
                    config,
                ))),
                downloads_finished: 0,
            },
            fresh: HashSet::new(),
            requested_update: false,
            fetch_started: false,
            registry_config: None,
            auth_required: false,
            login_url: None,
        })
    }

    fn handle_http_header(buf: &[u8]) -> Option<(&str, &str)> {
        if buf.is_empty() {
            return None;
        }
        let buf = std::str::from_utf8(buf).ok()?.trim_end();
        // Don't let server sneak extra lines anywhere.
        if buf.contains('\n') {
            return None;
        }
        let (tag, value) = buf.split_once(':')?;
        let value = value.trim();
        Some((tag, value))
    }

    fn start_fetch(&mut self) -> CargoResult<()> {
        if self.fetch_started {
            // We only need to run the setup code once.
            return Ok(());
        }
        self.fetch_started = true;

        // We've enabled the `http2` feature of `curl` in Cargo, so treat
        // failures here as fatal as it would indicate a build-time problem.
        self.multiplexing = self.config.http_config()?.multiplexing.unwrap_or(true);

        self.multi
            .pipelining(false, self.multiplexing)
            .with_context(|| "failed to enable multiplexing/pipelining in curl")?;

        // let's not flood the server with connections
        self.multi.set_max_host_connections(2)?;

        self.config
            .shell()
            .status("Updating", self.source_id.display_index())?;

        Ok(())
    }

    fn handle_completed_downloads(&mut self) -> CargoResult<()> {
        assert_eq!(
            self.downloads.pending.len(),
            self.downloads.pending_ids.len()
        );

        // Collect the results from the Multi handle.
        let pending = &mut self.downloads.pending;
        self.multi.messages(|msg| {
            let token = msg.token().expect("failed to read token");
            let (_, handle) = &pending[&token];
            let result = match msg.result_for(handle) {
                Some(result) => result,
                None => return, // transfer is not yet complete.
            };

            let (download, mut handle) = pending.remove(&token).unwrap();
            self.downloads.pending_ids.remove(&download.path).unwrap();

            let result = match result {
                Ok(()) => {
                    self.downloads.downloads_finished += 1;
                    match handle.response_code() {
                        Ok(code) => Ok(CompletedDownload {
                            response_code: code,
                            data: download.data.take(),
                            header_map: download.header_map.take(),
                        }),
                        Err(e) => Err(e),
                    }
                }
                Err(e) => Err(e),
            };
            self.downloads.results.insert(download.path, result);
        });
        self.downloads.tick()?;

        Ok(())
    }

    fn full_url(&self, path: &Path) -> String {
        format!("{}{}", self.url, path.display())
    }

    fn is_fresh(&self, path: &Path) -> bool {
        if !self.requested_update {
            trace!(
                "using local {} as user did not request update",
                path.display()
            );
            true
        } else if self.config.cli_unstable().no_index_update {
            trace!("using local {} in no_index_update mode", path.display());
            true
        } else if self.config.offline() {
            trace!("using local {} in offline mode", path.display());
            true
        } else if self.fresh.contains(path) {
            trace!("using local {} as it was already fetched", path.display());
            true
        } else {
            debug!("checking freshness of {}", path.display());
            false
        }
    }

    fn config_internal(&mut self) -> Poll<CargoResult<&RegistryConfig>> {
        if self.registry_config.is_some() {
            return Poll::Ready(Ok(self.registry_config.as_ref().unwrap()));
        }
        debug!("loading config");
        let index_path = self.assert_index_locked(&self.index_path);
        let config_json_path = index_path.join("config.json");
        if self.is_fresh(Path::new("config.json")) {
            match fs::read(&config_json_path) {
                Ok(raw_data) => match serde_json::from_slice(&raw_data) {
                    Ok(json) => {
                        self.registry_config = Some(json);
                        return Poll::Ready(Ok(self.registry_config.as_ref().unwrap()));
                    }
                    Err(e) => log::debug!("failed to decode cached config.json: {}", e),
                },
                Err(e) => log::debug!("failed to read config.json cache: {}", e),
            }
        }

        match self.load(Path::new(""), Path::new("config.json"), None)? {
            Poll::Ready(LoadResponse::Data {
                raw_data,
                index_version: _,
            }) => {
                trace!("config loaded");
                self.registry_config = Some(serde_json::from_slice(&raw_data)?);
                if paths::create_dir_all(&config_json_path.parent().unwrap()).is_ok() {
                    if let Err(e) = fs::write(&config_json_path, &raw_data) {
                        log::debug!("failed to write config.json cache: {}", e);
                    }
                }
                Poll::Ready(Ok(self.registry_config.as_ref().unwrap()))
            }
            Poll::Ready(LoadResponse::NotFound) => {
                Poll::Ready(Err(anyhow::anyhow!("config.json not found in registry")))
            }
            Poll::Ready(LoadResponse::CacheValid) => {
                panic!("config.json is not stored in the index cache")
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<'cfg> RegistryData for HttpRegistry<'cfg> {
    fn prepare(&self) -> CargoResult<()> {
        Ok(())
    }

    fn index_path(&self) -> &Filesystem {
        &self.index_path
    }

    fn assert_index_locked<'a>(&self, path: &'a Filesystem) -> &'a Path {
        self.config.assert_package_cache_locked(path)
    }

    fn is_updated(&self) -> bool {
        self.requested_update
    }

    fn load(
        &mut self,
        _root: &Path,
        path: &Path,
        index_version: Option<&str>,
    ) -> Poll<CargoResult<LoadResponse>> {
        trace!("load: {}", path.display());
        if let Some(_token) = self.downloads.pending_ids.get(path) {
            debug!("dependency is still pending: {}", path.display());
            return Poll::Pending;
        }

        if let Some(index_version) = index_version {
            trace!(
                "local cache of {} is available at version `{}`",
                path.display(),
                index_version
            );
            if self.is_fresh(path) {
                return Poll::Ready(Ok(LoadResponse::CacheValid));
            }
        } else if self.fresh.contains(path) {
            // We have no cached copy of this file, and we already downloaded it.
            debug!(
                "cache did not contain previously downloaded file {}",
                path.display()
            );
            return Poll::Ready(Ok(LoadResponse::NotFound));
        }

        if let Some(result) = self.downloads.results.remove(path) {
            let result =
                result.with_context(|| format!("download of {} failed", path.display()))?;
            debug!(
                "index file downloaded with status code {}",
                result.response_code
            );

            assert!(
                self.fresh.insert(path.to_path_buf()),
                "downloaded the index file `{}` twice",
                path.display()
            );

            match result.response_code {
                200 => {
                    let response_index_version = if let Some(etag) = result.header_map.etag {
                        format!("{}: {}", ETAG, etag)
                    } else if let Some(lm) = result.header_map.last_modified {
                        format!("{}: {}", LAST_MODIFIED, lm)
                    } else {
                        UNKNOWN.to_string()
                    };
                    trace!("index file version: {}", response_index_version);
                    return Poll::Ready(Ok(LoadResponse::Data {
                        raw_data: result.data,
                        index_version: Some(response_index_version),
                    }));
                }
                304 => {
                    // Not Modified: the data in the cache is still the latest.
                    if index_version.is_none() {
                        return Poll::Ready(Err(anyhow::anyhow!(
                            "server said not modified (HTTP 304) when no local cache exists"
                        )));
                    }
                    return Poll::Ready(Ok(LoadResponse::CacheValid));
                }
                404 | 410 | 451 => {
                    // The crate was not found or deleted from the registry.
                    return Poll::Ready(Ok(LoadResponse::NotFound));
                }
                401 if !self.auth_required && path == Path::new("config.json") => {
                    debug!("re-attempting request for config.json with authorization included.");
                    self.fresh.remove(path);
                    self.auth_required = true;

                    // Look for a `www-authenticate` header with the `Cargo` scheme.
                    for header in &result.header_map.www_authenticate {
                        for challenge in http_auth::ChallengeParser::new(header) {
                            match challenge {
                                Ok(challenge) if challenge.scheme.eq_ignore_ascii_case("Cargo") => {
                                    // Look for the `login_url` parameter.
                                    for (param, value) in challenge.params {
                                        if param.eq_ignore_ascii_case("login_url") {
                                            self.login_url = Some(value.to_unescaped().into_url()?);
                                        }
                                    }
                                }
                                Ok(challenge) => {
                                    debug!("ignoring non-Cargo challenge: {}", challenge.scheme)
                                }
                                Err(e) => debug!("failed to parse challenge: {}", e),
                            }
                        }
                    }
                }
                401 if self.auth_required => {
                    let body = String::from_utf8_lossy(&result.data);
                    let body = truncate_with_ellipsis(&body, 1000);
                    let err = anyhow::anyhow!("remote server said: {}", body,).context(
                        auth::AuthorizationError {
                            sid: self.source_id.clone(),
                            login_url: self.login_url.clone(),
                            message: "token rejected",
                        },
                    );
                    return Poll::Ready(Err(err));
                }
                code => {
                    let body = String::from_utf8_lossy(&result.data);
                    let body = truncate_with_ellipsis(&body, 1000);
                    return Poll::Ready(Err(anyhow::anyhow!(
                        "remote server responded with unexpected HTTP {} for '{}'\nmessage from server: {}",
                        code,
                        self.full_url(path),
                        body,
                    )));
                }
            }
        }

        // Load the registry config.
        if self.registry_config.is_none() && path != Path::new("config.json") {
            match self.config_internal()? {
                Poll::Ready(config) => {
                    self.auth_required = config.auth_required;
                }
                Poll::Pending => return Poll::Pending,
            }
        };

        // Looks like we're going to have to do a network request.
        self.start_fetch()?;

        let mut handle = ops::http_handle(self.config)?;
        let full_url = self.full_url(path);
        debug!("fetch {}", full_url);
        handle.get(true)?;
        handle.url(&full_url)?;
        handle.follow_location(true)?;

        // Enable HTTP/2 if possible.
        if self.multiplexing {
            handle.http_version(HttpVersion::V2)?;
        } else {
            handle.http_version(HttpVersion::V11)?;
        }

        // This is an option to `libcurl` which indicates that if there's a
        // bunch of parallel requests to the same host they all wait until the
        // pipelining status of the host is known. This means that we won't
        // initiate dozens of connections to crates.io, but rather only one.
        // Once the main one is opened we realized that pipelining is possible
        // and multiplexing is possible with static.crates.io. All in all this
        // reduces the number of connections done to a more manageable state.
        handle.pipewait(true)?;

        let mut headers = List::new();
        headers.append("cargo-protocol: version=1")?;
        headers.append("accept: text/plain")?;

        // If we have a cached copy of the file, include IF_NONE_MATCH or IF_MODIFIED_SINCE header.
        if let Some(index_version) = index_version {
            if let Some((key, value)) = index_version.split_once(':') {
                match key {
                    ETAG => headers.append(&format!("{}: {}", IF_NONE_MATCH, value.trim()))?,
                    LAST_MODIFIED => {
                        headers.append(&format!("{}: {}", IF_MODIFIED_SINCE, value.trim()))?
                    }
                    _ => debug!("unexpected index version: {}", index_version),
                }
            }
        }
        if self.auth_required {
            if !self.config.cli_unstable().registry_auth {
                return Poll::Ready(Err(anyhow::anyhow!(
                    "authenticated registries require `-Z registry-auth`"
                )));
            }
            let authorization =
                auth::auth_token(self.config, &self.source_id, self.login_url.as_ref())?;
            headers.append(&format!("authorization: {}", authorization))?;
            trace!("including authorization for {}", full_url);
        }
        handle.http_headers(headers)?;

        // We're going to have a bunch of downloads all happening "at the same time".
        // So, we need some way to track what headers/data/responses are for which request.
        // We do that through this token. Each request (and associated response) gets one.
        let token = self.downloads.next;
        self.downloads.next += 1;
        debug!("downloading {} as {}", path.display(), token);
        assert_eq!(
            self.downloads.pending_ids.insert(path.to_path_buf(), token),
            None,
            "path queued for download more than once"
        );

        // Each write should go to self.downloads.pending[&token].data.
        // Since the write function must be 'static, we access downloads through a thread-local.
        // That thread-local is set up in `block_until_ready` when it calls self.multi.perform,
        // which is what ultimately calls this method.
        handle.write_function(move |buf| {
            trace!("{} - {} bytes of data", token, buf.len());
            tls::with(|downloads| {
                if let Some(downloads) = downloads {
                    downloads.pending[&token]
                        .0
                        .data
                        .borrow_mut()
                        .extend_from_slice(buf);
                }
            });
            Ok(buf.len())
        })?;

        // Same goes for the progress function -- it goes through thread-local storage.
        handle.progress(true)?;
        handle.progress_function(move |dl_total, dl_cur, _, _| {
            tls::with(|downloads| match downloads {
                Some(d) => d.progress(token, dl_total as u64, dl_cur as u64),
                None => false,
            })
        })?;

        // And ditto for the header function.
        handle.header_function(move |buf| {
            if let Some((tag, value)) = Self::handle_http_header(buf) {
                tls::with(|downloads| {
                    if let Some(downloads) = downloads {
                        let mut header_map = downloads.pending[&token].0.header_map.borrow_mut();
                        match tag.to_ascii_lowercase().as_str() {
                            LAST_MODIFIED => header_map.last_modified = Some(value.to_string()),
                            ETAG => header_map.etag = Some(value.to_string()),
                            WWW_AUTHENTICATE => header_map.www_authenticate.push(value.to_string()),
                            _ => {}
                        }
                    }
                });
            }

            true
        })?;

        let dl = Download {
            token,
            path: path.to_path_buf(),
            data: RefCell::new(Vec::new()),
            header_map: Default::default(),
            total: Cell::new(0),
            current: Cell::new(0),
        };

        // Finally add the request we've lined up to the pool of requests that cURL manages.
        let mut handle = self.multi.add(handle)?;
        handle.set_token(token)?;
        self.downloads.pending.insert(dl.token, (dl, handle));

        Poll::Pending
    }

    fn config(&mut self) -> Poll<CargoResult<Option<RegistryConfig>>> {
        match self.config_internal()? {
            Poll::Pending => Poll::Pending,
            Poll::Ready(cfg) => {
                let cfg = cfg.clone();
                if cfg.auth_required && !self.config.cli_unstable().registry_auth {
                    return Poll::Ready(Err(anyhow::anyhow!(
                        "authenticated registries require `-Z registry-auth`"
                    )));
                }
                Poll::Ready(Ok(Some(cfg)))
            }
        }
    }

    fn invalidate_cache(&mut self) {
        // Actually updating the index is more or less a no-op for this implementation.
        // All it does is ensure that a subsequent load will double-check files with the
        // server rather than rely on a locally cached copy of the index files.
        debug!("invalidated index cache");
        self.requested_update = true;
    }

    fn download(&mut self, pkg: PackageId, checksum: &str) -> CargoResult<MaybeLock> {
        let registry_config = loop {
            match self.config()? {
                Poll::Pending => self.block_until_ready()?,
                Poll::Ready(cfg) => break cfg.unwrap(),
            }
        };
        download::download(
            &self.cache_path,
            &self.config,
            pkg,
            checksum,
            registry_config,
        )
    }

    fn finish_download(
        &mut self,
        pkg: PackageId,
        checksum: &str,
        data: &[u8],
    ) -> CargoResult<File> {
        download::finish_download(&self.cache_path, &self.config, pkg, checksum, data)
    }

    fn is_crate_downloaded(&self, pkg: PackageId) -> bool {
        download::is_crate_downloaded(&self.cache_path, &self.config, pkg)
    }

    fn block_until_ready(&mut self) -> CargoResult<()> {
        let initial_pending_count = self.downloads.pending.len();
        trace!(
            "block_until_ready: {} transfers pending",
            initial_pending_count
        );

        loop {
            self.handle_completed_downloads()?;

            let remaining_in_multi = tls::set(&self.downloads, || {
                self.multi
                    .perform()
                    .with_context(|| "failed to perform http requests")
            })?;
            trace!("{} transfers remaining", remaining_in_multi);

            if remaining_in_multi == 0 {
                return Ok(());
            }

            // We have no more replies to provide the caller with,
            // so we need to wait until cURL has something new for us.
            let timeout = self
                .multi
                .get_timeout()?
                .unwrap_or_else(|| Duration::new(5, 0));
            self.multi
                .wait(&mut [], timeout)
                .with_context(|| "failed to wait on curl `Multi`")?;
        }
    }
}

impl<'cfg> Downloads<'cfg> {
    fn progress(&self, token: usize, total: u64, cur: u64) -> bool {
        let dl = &self.pending[&token].0;
        dl.total.set(total);
        dl.current.set(cur);
        true
    }

    fn tick(&self) -> CargoResult<()> {
        let mut progress = self.progress.borrow_mut();
        let progress = progress.as_mut().unwrap();

        progress.tick(
            self.downloads_finished,
            self.downloads_finished + self.pending.len(),
            "",
        )
    }
}

mod tls {
    use super::Downloads;
    use std::cell::Cell;

    thread_local!(static PTR: Cell<usize> = Cell::new(0));

    pub(crate) fn with<R>(f: impl FnOnce(Option<&Downloads<'_>>) -> R) -> R {
        let ptr = PTR.with(|p| p.get());
        if ptr == 0 {
            f(None)
        } else {
            let ptr = unsafe { &*(ptr as *const Downloads<'_>) };
            f(Some(ptr))
        }
    }

    pub(crate) fn set<R>(dl: &Downloads<'_>, f: impl FnOnce() -> R) -> R {
        struct Reset<'a, T: Copy>(&'a Cell<T>, T);

        impl<'a, T: Copy> Drop for Reset<'a, T> {
            fn drop(&mut self) {
                self.0.set(self.1);
            }
        }

        PTR.with(|p| {
            let _reset = Reset(p, p.get());
            p.set(dl as *const Downloads<'_> as usize);
            f()
        })
    }
}
