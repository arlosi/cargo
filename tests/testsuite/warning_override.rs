//! Tests for overriding warning behavior using `build.warnings` config option.

use std::sync::LazyLock;

use cargo_test_support::{cargo_test, project, str, Project};
use snapbox::data::Inline;

const ALLOW_CLEAN: LazyLock<Inline> = LazyLock::new(|| {
    str![[r#"
[CHECKING] foo v0.0.1 ([ROOT]/foo)
[FINISHED] `dev` profile [unoptimized + debuginfo] target(s) in [ELAPSED]s

"#]]
});

const ALLOW_CACHED: LazyLock<Inline> = LazyLock::new(|| {
    str![[r#"
[FINISHED] `dev` profile [unoptimized + debuginfo] target(s) in [ELAPSED]s

"#]]
});

static WARN: LazyLock<Inline> = LazyLock::new(|| {
    str![[r#"
...
[WARNING] unused variable: `x`
...
[WARNING] `foo` (bin "foo") generated 1 warning
[FINISHED] `dev` profile [unoptimized + debuginfo] target(s) in [ELAPSED]s

"#]]
});

const DENY: LazyLock<Inline> = LazyLock::new(|| {
    str![[r#"
...
[WARNING] unused variable: `x`
...
[WARNING] `foo` (bin "foo") generated 1 warning
[FINISHED] `dev` profile [unoptimized + debuginfo] target(s) in [ELAPSED]s
[ERROR] warnings are denied by `build.warnings` configuration

"#]]
});

fn make_project(main_src: &str) -> Project {
    project()
        .file(
            "Cargo.toml",
            &format!(
                r#"
                [package]
                name = "foo"
                version = "0.0.1"
                edition = "2021"
            "#
            ),
        )
        .file("src/main.rs", &format!("fn main() {{ {} }}", main_src))
        .build()
}

#[cargo_test]
fn rustc_caching_allow_first() {
    let p = make_project("let x = 3;");
    p.cargo("check")
        .masquerade_as_nightly_cargo(&["warnings"])
        .arg("-Zwarnings")
        .arg("--config")
        .arg("build.warnings='allow'")
        .with_stderr_data(ALLOW_CLEAN.clone())
        .run();

    p.cargo("check")
        .masquerade_as_nightly_cargo(&["warnings"])
        .arg("-Zwarnings")
        .arg("--config")
        .arg("build.warnings='deny'")
        .with_stderr_data(DENY.clone())
        .with_status(101)
        .run();
}

#[cargo_test]
fn rustc_caching_deny_first() {
    let p = make_project("let x = 3;");
    p.cargo("check")
        .masquerade_as_nightly_cargo(&["warnings"])
        .arg("-Zwarnings")
        .arg("--config")
        .arg("build.warnings='deny'")
        .with_stderr_data(DENY.clone())
        .with_status(101)
        .run();

    p.cargo("check")
        .masquerade_as_nightly_cargo(&["warnings"])
        .arg("-Zwarnings")
        .arg("--config")
        .arg("build.warnings='allow'")
        .with_stderr_data(ALLOW_CACHED.clone())
        .run();
}

#[cargo_test]
fn config() {
    let p = make_project("let x = 3;");
    p.cargo("check")
        .masquerade_as_nightly_cargo(&["warnings"])
        .arg("-Zwarnings")
        .env("CARGO_BUILD_WARNINGS", "deny")
        .with_stderr_data(DENY.clone())
        .with_status(101)
        .run();

    // CLI has precedence over env
    p.cargo("check")
        .masquerade_as_nightly_cargo(&["warnings"])
        .arg("-Zwarnings")
        .arg("--config")
        .arg("build.warnings='warn'")
        .env("CARGO_BUILD_WARNINGS", "deny")
        .with_stderr_data(WARN.clone())
        .run();
}

#[cargo_test]
fn requires_nightly() {
    // build.warnings has no effect without -Zwarnings.
    let p = make_project("let x = 3;");
    p.cargo("check")
        .arg("--config")
        .arg("build.warnings='deny'")
        .with_stderr_data(WARN.clone())
        .run();
}
