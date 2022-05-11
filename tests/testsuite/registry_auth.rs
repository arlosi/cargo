//! Tests for normal registry dependencies.

use cargo_test_support::registry::{Package, RegistryBuilder};
use cargo_test_support::{project, Execs, Project};

fn cargo(p: &Project, s: &str) -> Execs {
    let mut e = p.cargo(s);
    e.masquerade_as_nightly_cargo()
        .arg("-Zhttp-registry")
        .arg("-Zregistry-auth");
    e
}

fn make_project() -> Project {
    let p = project()
        .file(
            "Cargo.toml",
            r#"
                [project]
                name = "foo"
                version = "0.0.1"
                authors = []

                [dependencies.bar]
                version = "0.0.1"
                registry = "alternative"
            "#,
        )
        .file("src/main.rs", "fn main() {}")
        .build();
    Package::new("bar", "0.0.1").alternative(true).publish();
    p
}

static SUCCCESS_OUTPUT: &'static str = "\
[UPDATING] `alternative` index
[DOWNLOADING] crates ...
[DOWNLOADED] bar v0.0.1 (registry `alternative`)
[COMPILING] bar v0.0.1 (registry `alternative`)
[COMPILING] foo v0.0.1 ([CWD])
[FINISHED] dev [unoptimized + debuginfo] target(s) in [..]s
";

#[cargo_test]
fn requires_nightly() {
    let _registry = RegistryBuilder::new().alternative().auth_required().build();

    let p = make_project();
    p.cargo("build")
        .with_status(101)
        .with_stderr_contains("  authenticated registries require `-Z registry-auth`")
        .run();
}

#[cargo_test]
fn simple() {
    let _registry = RegistryBuilder::new()
        .alternative()
        .auth_required()
        .http_index()
        .build();

    let p = make_project();
    cargo(&p, "build").with_stderr(SUCCCESS_OUTPUT).run();
}

#[cargo_test]
fn environment_config() {
    let registry = RegistryBuilder::new()
        .alternative()
        .auth_required()
        .no_configure_registry()
        .no_configure_token()
        .http_index()
        .build();
    let p = make_project();
    cargo(&p, "build")
        .env(
            "CARGO_REGISTRIES_ALTERNATIVE_INDEX",
            registry.index_url().as_str(),
        )
        .env("CARGO_REGISTRIES_ALTERNATIVE_TOKEN", registry.token())
        .with_stderr(SUCCCESS_OUTPUT)
        .run();
}

#[cargo_test]
fn environment_token() {
    let registry = RegistryBuilder::new()
        .alternative()
        .auth_required()
        .no_configure_token()
        .http_index()
        .build();

    let p = make_project();
    cargo(&p, "build")
        .env("CARGO_REGISTRIES_ALTERNATIVE_TOKEN", registry.token())
        .with_stderr(SUCCCESS_OUTPUT)
        .run();
}

#[cargo_test]
fn missing_token() {
    let _registry = RegistryBuilder::new()
        .alternative()
        .auth_required()
        .no_configure_token()
        .http_index()
        .build();

    let p = make_project();
    cargo(&p, "build")
        .with_status(101)
        .with_stderr(
            "\
[UPDATING] `alternative` index
[ERROR] failed to get `bar` as a dependency of package `foo v0.0.1 ([..])`

Caused by:
  no token found for `alternative`, please run `cargo login --registry alternative`",
        )
        .run();
}

#[cargo_test]
fn missing_token_git() {
    let _registry = RegistryBuilder::new()
        .alternative()
        .auth_required()
        .no_configure_token()
        .build();

    let p = make_project();
    cargo(&p, "build")
        .with_status(101)
        .with_stderr(
            "\
[UPDATING] `alternative` index
[ERROR] failed to download `bar v0.0.1 (registry `alternative`)`

Caused by:
  unable to get packages from source

Caused by:
  no token found for `alternative`, please run `cargo login --registry alternative`",
        )
        .run();
}

#[cargo_test]
fn incorrect_token() {
    let _registry = RegistryBuilder::new()
        .alternative()
        .auth_required()
        .no_configure_token()
        .http_index()
        .build();

    let p = make_project();
    cargo(&p, "build")
        .env("CARGO_REGISTRIES_ALTERNATIVE_TOKEN", "incorrect")
        .with_status(101)
        .with_stderr(
            "\
[UPDATING] `alternative` index
[ERROR] failed to get `bar` as a dependency of package `foo v0.0.1 ([..])`

Caused by:
  token rejected for `alternative`, please run `cargo login --registry alternative`

Caused by:
  remote server said: Unauthorized message from server.",
        )
        .run();
}

#[cargo_test]
fn incorrect_token_git() {
    let _registry = RegistryBuilder::new()
        .alternative()
        .auth_required()
        .no_configure_token()
        .http_api()
        .build();

    let p = make_project();
    cargo(&p, "build")
        .env("CARGO_REGISTRIES_ALTERNATIVE_TOKEN", "incorrect")
        .with_status(101)
        .with_stderr(
            "\
[UPDATING] `alternative` index
[DOWNLOADING] crates ...
[ERROR] failed to download from `http://[..]/dl/bar/0.0.1/download`

Caused by:
  failed to get 200 response from `http://[..]/dl/bar/0.0.1/download`, got 401",
        )
        .run();
}

#[cargo_test]
fn login() {
    let _registry = RegistryBuilder::new()
        .alternative()
        .no_configure_token()
        .auth_required()
        .http_index()
        .build();

    let p = make_project();
    cargo(&p, "login --registry alternative")
        .with_stdout("please paste the token found on https://test-registry-login/me below")
        .with_stdin("sekrit")
        .run();
}

#[cargo_test]
fn login_existing_token() {
    let _registry = RegistryBuilder::new()
        .alternative()
        .auth_required()
        .http_index()
        .build();

    let p = make_project();
    cargo(&p, "login --registry alternative")
        .with_stdout("please paste the token found on file://[..]/me below")
        .with_stdin("sekrit")
        .run();
}

#[cargo_test]
fn duplicate_index() {
    let server = RegistryBuilder::new()
        .alternative()
        .no_configure_token()
        .auth_required()
        .build();
    let p = make_project();

    // Two alternative registries with the same index.
    cargo(&p, "build")
        .env(
            "CARGO_REGISTRIES_ALTERNATIVE1_INDEX",
            server.index_url().as_str(),
        )
        .env(
            "CARGO_REGISTRIES_ALTERNATIVE2_INDEX",
            server.index_url().as_str(),
        )
        .with_status(101)
        .with_stderr(
            "\
[UPDATING] `alternative` index
[ERROR] failed to download `bar v0.0.1 (registry `alternative`)`

Caused by:
  unable to get packages from source

Caused by:
  multiple registries are configured with the same index url \
  'file://[..]/alternative-registry': ALTERNATIVE1, ALTERNATIVE2
",
        )
        .run();
}
