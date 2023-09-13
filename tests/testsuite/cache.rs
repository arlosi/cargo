//! Tests for per-user caching.

use cargo_test_support::project;
use cargo_test_support::registry::Package;

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
        .file("src/lib.rs", "extern crate bar; extern crate baz;")
        .build();

    p.cargo("build").run();
    p.cargo("clean").run();
    p.cargo("build")
        .with_stderr(
            "\
[CACHED] bar v0.1.0
[CACHED] baz v0.2.0
[COMPILING] foo v0.0.1 [..]
[FINISHED] [..]",
        )
        .run();
}
