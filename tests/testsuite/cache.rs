//! Tests for per-user caching.

use cargo_test_support::project;
use cargo_test_support::registry::Package;

/// Test that -Z shared-user-cache, configured properly on nightly, works as expected.
#[cargo_test]
fn simple() {
    Package::new("bar", "0.1.0").publish();
    Package::new("baz", "0.2.0").publish();

    let p = project()
        .file(
            "Cargo.toml",
            r#"
                [package]
                name = "foo"
                version = "0.0.1"
                authors = []

                [dependencies]
                bar = { version = "0.1.0" }
                baz = { version = "0.2.0" }
            "#,
        )
        .file(
            ".cargo/config.toml",
            r#"
                [shared_user_cache]
                path = "artifact_cache"
                "#,
        )
        .file("src/lib.rs", "extern crate bar; extern crate baz;")
        .build();

    p.cargo("build -Z shared-user-cache")
        .masquerade_as_nightly_cargo(&["shared-user-cache"])
        .run();
    p.cargo("clean").run();
    p.cargo("build -Z shared-user-cache")
        .masquerade_as_nightly_cargo(&["shared-user-cache"])
        .with_stderr(
            "\
[CACHED] bar v0.1.0
[CACHED] baz v0.2.0
[COMPILING] foo v0.0.1 [..]
[FINISHED] [..]",
        )
        .run();
}

#[cargo_test]
fn requires_nightly() {
    Package::new("bar", "0.1.0").publish();
    Package::new("baz", "0.2.0").publish();

    let p = project()
        .file(
            "Cargo.toml",
            r#"
                [package]
                name = "foo"
                version = "0.0.1"
                authors = []

                [dependencies]
                bar = { version = "0.1.0" }
                baz = { version = "0.2.0" }
            "#,
        )
        .file(
            ".cargo/config.toml",
            r#"
                [shared_user_cache]
                path = "artifact_cache"
                "#,
        )
        .file("src/lib.rs", "extern crate bar; extern crate baz;")
        .build();

    p.cargo("build")
        .with_stderr(
            "\
[UPDATING] [..]
[DOWNLOADING] crates ...
[DOWNLOADED] [..]
[DOWNLOADED] [..]
[COMPILING] [..]
[COMPILING] [..]
[COMPILING] [..]
[FINISHED] [..]",
        )
        .run();
}
