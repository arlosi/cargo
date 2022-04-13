//! Registry authentication support.

use crate::util::{config, CargoResult, Config};
use anyhow::{bail, format_err, Context as _};
use cargo_util::ProcessError;
use core::fmt;
use serde::Deserialize;
use std::collections::HashMap;
use std::error::Error;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use url::Url;

use crate::core::SourceId;
use crate::ops::RegistryCredentialConfig;

/// Get the credential configuration for a `SourceId`.
pub fn registry_credential_config(
    config: &Config,
    sid: &SourceId,
) -> CargoResult<RegistryCredentialConfig> {
    #[derive(Deserialize)]
    #[serde(rename_all = "kebab-case")]
    struct RegistryConfig {
        index: Option<String>,
        token: Option<String>,
        credential_process: Option<config::PathAndArgs>,
    }

    log::trace!("loading credential config for {}", sid);
    if !sid.is_remote_registry() {
        bail!(
            "{} does not support API commands.\n\
             Check for a source-replacement in .cargo/config.",
            sid
        );
    }

    // Handle crates.io specially, since it uses different configuration keys.
    if sid.is_default_registry() {
        config.check_registry_index_not_set()?;
        let process = config.get::<Option<config::PathAndArgs>>("registry.credential-process")?;
        let credential = if process.is_some() && config.cli_unstable().credential_process {
            let process = process.unwrap();
            RegistryCredentialConfig::Process((process.path.resolve_program(config), process.args))
        } else if let Some(token) = config.get_string("registry.token")?.map(|p| p.val) {
            RegistryCredentialConfig::Token(token)
        } else {
            RegistryCredentialConfig::None
        };
        return Ok(credential);
    }

    // A `SourceId` usually has a name, but it may not. If a name is not available,
    // try to find one by reading configuration and environment variables.
    let name = {
        // Discover names from environment variables.
        let index = sid.url().as_str();
        let mut names: Vec<_> = config
            .env()
            .iter()
            .filter(|(_, v)| v.as_str() == index)
            .filter_map(|(k, _)| {
                k.strip_prefix("CARGO_REGISTRIES_")
                    .and_then(|k| k.strip_suffix("_INDEX"))
            })
            .map(|s| s.to_string())
            .collect();
        if names.len() == 0 {
            // Discover names from the configuration if none were found in the environment.
            names = config
                .get::<HashMap<String, RegistryConfig>>("registries")?
                .iter()
                .filter(|(_, v)| v.index.as_deref() == Some(index))
                .map(|(k, _)| k.to_string())
                .collect();
        }
        names.sort();
        match names.len() {
            0 => None,
            1 => Some(names[0].to_string()),
            _ => anyhow::bail!(
                "multiple registries are configured with the same index url '{}': {}",
                &sid.url(),
                names.join(", ")
            ),
        }
    };

    // It's possible to have a registry configured in a Cargo config file,
    // then override it with configuration from environment variables.
    if let Some(cfg_name) = sid.cfg_name() {
        if let Some(name) = name.as_deref() {
            if cfg_name != name {
                log::debug!("name of alternative registry with url `{}` overridden from `{}` to `{}` by environment", 
                    sid.url().as_str(), cfg_name, name);
            }
        }
    }

    if let Some(name) = name {
        log::debug!("found alternative registry name `{name}` for {sid} ");
        match config.get::<RegistryConfig>(&format!("registries.{name}"))? {
            RegistryConfig {
                index: _,
                token: Some(token),
                credential_process: _,
            } if !config.cli_unstable().credential_process => {
                return Ok(RegistryCredentialConfig::Token(token))
            }
            RegistryConfig {
                index: _,
                token: None,
                credential_process: _,
            } if !config.cli_unstable().credential_process => {
                return Ok(RegistryCredentialConfig::None)
            }
            RegistryConfig {
                index: _,
                token: Some(token),
                credential_process: None,
            } => return Ok(RegistryCredentialConfig::Token(token)),
            RegistryConfig {
                index: _,
                token: None,
                credential_process: Some(process),
            } => {
                return Ok(RegistryCredentialConfig::Process((
                    process.path.resolve_program(config),
                    process.args,
                )))
            }
            RegistryConfig {
                index: _,
                token: Some(_),
                credential_process: Some(_),
            } => anyhow::bail!(
                "both `token` and `credential-process` \
                were specified in the config for registry `{}`.\n\
                Only one of these values may be set, remove one or the other to proceed.",
                name
            ),
            RegistryConfig {
                index: _,
                token: None,
                credential_process: None,
            } => {}
        }
    }

    if config.cli_unstable().credential_process {
        // If we couldn't find a registry-specific credential, try the global credential process.
        if let Some(process) =
            config.get::<Option<config::PathAndArgs>>("registry.credential-process")?
        {
            return Ok(RegistryCredentialConfig::Process((
                process.path.resolve_program(config),
                process.args,
            )));
        }
    }

    // No credential available.
    Ok(RegistryCredentialConfig::None)
}

/// An authorization error from accessing a registry.
#[derive(Debug)]
pub struct AuthorizationError {
    /// Url that was attempted
    pub sid: SourceId,
    /// Url where the user could log in.
    pub login_url: Option<Url>,
    /// Specific message indicating what failed, such as "no token"
    pub message: &'static str,
}
impl Error for AuthorizationError {}
impl fmt::Display for AuthorizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.sid.is_default_registry() {
            write!(f, "{}, please run `cargo login`", self.message)
        } else if let Some(name) = self.sid.cfg_name() {
            write!(
                f,
                "{} for `{}`, please run `cargo login --registry {}`",
                self.message,
                self.sid.display_registry_name(),
                name
            )
        } else {
            write!(
                f,
                r#"{} for `{}`
consider setting up an alternate registry in Cargo's configuration
as described by https://doc.rust-lang.org/cargo/reference/registries.html

[registries]
my-registry = {{ index = "{}" }}
"#,
                self.message,
                self.sid.display_registry_name(),
                self.sid.url()
            )
        }
    }
}

// Store a token in the cache for future calls.
pub fn cache_token(config: &Config, sid: &SourceId, token: &str) {
    let url = sid.canonical_url();
    config
        .credential_cache()
        .insert(url.clone(), token.to_string());
}

/// Returns the token to use for the given registry.
/// If a command_line_token is present, it will be returned and
/// cached for future calls using the same SourceId.
pub fn auth_token(config: &Config, sid: &SourceId, login_url: Option<&Url>) -> CargoResult<String> {
    match auth_token_optional(config, sid)? {
        Some(token) => Ok(token),
        None => Err(AuthorizationError {
            sid: sid.clone(),
            login_url: login_url.cloned(),
            message: "no token found",
        }
        .into()),
    }
}

/// Returns the token to use for the given registry.
fn auth_token_optional(config: &Config, sid: &SourceId) -> CargoResult<Option<String>> {
    let mut cache = config.credential_cache();
    let url = sid.canonical_url();

    if let Some(token) = cache.get(url) {
        return Ok(Some(token.clone()));
    }

    let credential = registry_credential_config(config, sid)?;
    let token = match credential {
        RegistryCredentialConfig::None => return Ok(None),
        RegistryCredentialConfig::Token(config_token) => config_token.to_string(),
        RegistryCredentialConfig::Process(process) => {
            run_command(config, &process, sid, Action::Get)?.unwrap()
        }
    };

    cache.insert(url.clone(), token.clone());
    Ok(Some(token))
}

enum Action {
    Get,
    Store(String),
    Erase,
}

/// Saves the given token.
pub fn login(config: &Config, sid: &SourceId, token: String) -> CargoResult<()> {
    match registry_credential_config(config, sid)? {
        RegistryCredentialConfig::Process(process) => {
            run_command(config, &process, sid, Action::Store(token))?;
        }
        _ => {
            config::save_credentials(config, Some(token), &sid)?;
        }
    };
    Ok(())
}

/// Removes the token for the given registry.
pub fn logout(config: &Config, sid: &SourceId) -> CargoResult<()> {
    match registry_credential_config(config, sid)? {
        RegistryCredentialConfig::Process(process) => {
            run_command(config, &process, sid, Action::Erase)?;
        }
        _ => {
            config::save_credentials(config, None, &sid)?;
        }
    };
    Ok(())
}

fn run_command(
    config: &Config,
    process: &(PathBuf, Vec<String>),
    sid: &SourceId,
    action: Action,
) -> CargoResult<Option<String>> {
    let index_url = sid.url().as_str();
    let cred_proc;
    let (exe, args) = if process.0.to_str().unwrap_or("").starts_with("cargo:") {
        cred_proc = sysroot_credential(config, process)?;
        &cred_proc
    } else {
        process
    };
    if !args.iter().any(|arg| arg.contains("{action}")) {
        let msg = |which| {
            format!(
                "credential process `{}` cannot be used to {}, \
                 the credential-process configuration value must pass the \
                 `{{action}}` argument in the config to support this command",
                exe.display(),
                which
            )
        };
        match action {
            Action::Get => {}
            Action::Store(_) => bail!(msg("log in")),
            Action::Erase => bail!(msg("log out")),
        }
    }
    let action_str = match action {
        Action::Get => "get",
        Action::Store(_) => "store",
        Action::Erase => "erase",
    };
    let args: Vec<_> = args
        .iter()
        .map(|arg| {
            arg.replace("{action}", action_str)
                .replace("{index_url}", index_url)
        })
        .collect();

    let mut cmd = Command::new(&exe);
    cmd.args(args)
        .env("CARGO", config.cargo_exe()?)
        .env("CARGO_REGISTRY_INDEX_URL", index_url);
    if let Some(name) = sid.cfg_name() {
        cmd.env("CARGO_REGISTRY_NAME_OPT", name);
    }
    match action {
        Action::Get => {
            cmd.stdout(Stdio::piped());
        }
        Action::Store(_) => {
            cmd.stdin(Stdio::piped());
        }
        Action::Erase => {}
    }
    let mut child = cmd.spawn().with_context(|| {
        let verb = match action {
            Action::Get => "fetch",
            Action::Store(_) => "store",
            Action::Erase => "erase",
        };
        format!(
            "failed to execute `{}` to {} authentication token for registry `{}`",
            exe.display(),
            verb,
            sid.display_registry_name(),
        )
    })?;
    let mut token = None;
    match &action {
        Action::Get => {
            let mut buffer = String::new();
            log::debug!("reading into buffer");
            child
                .stdout
                .as_mut()
                .unwrap()
                .read_to_string(&mut buffer)
                .with_context(|| {
                    format!(
                        "failed to read token from registry credential process `{}`",
                        exe.display()
                    )
                })?;
            if let Some(end) = buffer.find('\n') {
                if buffer.len() > end + 1 {
                    bail!(
                        "credential process `{}` returned more than one line of output; \
                         expected a single token",
                        exe.display()
                    );
                }
                buffer.truncate(end);
            }
            token = Some(buffer);
        }
        Action::Store(token) => {
            writeln!(child.stdin.as_ref().unwrap(), "{}", token).with_context(|| {
                format!(
                    "failed to send token to registry credential process `{}`",
                    exe.display()
                )
            })?;
        }
        Action::Erase => {}
    }
    let status = child.wait().with_context(|| {
        format!(
            "registry credential process `{}` exit failure",
            exe.display()
        )
    })?;
    if !status.success() {
        let msg = match action {
            Action::Get => "failed to authenticate to registry",
            Action::Store(_) => "failed to store token to registry",
            Action::Erase => "failed to erase token from registry",
        };
        return Err(ProcessError::new(
            &format!(
                "registry credential process `{}` {} `{}`",
                exe.display(),
                msg,
                sid.display_registry_name()
            ),
            Some(status),
            None,
        )
        .into());
    }
    Ok(token)
}

/// Gets the path to the libexec processes in the sysroot.
fn sysroot_credential(
    config: &Config,
    process: &(PathBuf, Vec<String>),
) -> CargoResult<(PathBuf, Vec<String>)> {
    let cred_name = process.0.to_str().unwrap().strip_prefix("cargo:").unwrap();
    let cargo = config.cargo_exe()?;
    let root = cargo
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| format_err!("expected cargo path {}", cargo.display()))?;
    let exe = root.join("libexec").join(format!(
        "cargo-credential-{}{}",
        cred_name,
        std::env::consts::EXE_SUFFIX
    ));
    let mut args = process.1.clone();
    if !args.iter().any(|arg| arg == "{action}") {
        args.push("{action}".to_string());
    }
    Ok((exe, args))
}
