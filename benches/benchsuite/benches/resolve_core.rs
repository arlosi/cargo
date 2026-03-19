//! Benchmarks for `resolver::resolve()` with synthetic registries.
//!
//! These benchmarks exercise the resolver algorithm directly,
//! including the `LocalPollAdapter` async bridge and `RegistryQueryer` caching.
//! Unlike the `resolve` benchmark which uses real workspaces from crates.io,
//! these use synthetic dependency graphs of controlled sizes.

use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::task::Poll;

use cargo::core::resolver::{self, ResolveOpts, VersionPreferences};
use cargo::core::{Dependency, PackageId, Registry, ResolveVersion, SourceId, Summary};
use cargo::sources::IndexSummary;
use cargo::sources::source::QueryKind;
use cargo::util::{CargoResult, GlobalContext, IntoUrl};
use criterion::{Criterion, criterion_group, criterion_main};

fn registry_loc() -> SourceId {
    static LOC: OnceLock<SourceId> = OnceLock::new();
    *LOC.get_or_init(|| {
        SourceId::for_registry(&"https://example.com".into_url().unwrap()).unwrap()
    })
}

fn pkg_id(name: &str, version: &str) -> PackageId {
    PackageId::try_new(name, version, registry_loc()).unwrap()
}

fn dep(name: &str, req: &str) -> Dependency {
    Dependency::parse(name, Some(req), registry_loc()).unwrap()
}

fn summary(name: &str, version: &str, deps: Vec<Dependency>) -> Summary {
    Summary::new(
        pkg_id(name, version),
        deps,
        &BTreeMap::new(),
        None::<&String>,
        None,
    )
    .unwrap()
}

struct SyntheticRegistry {
    summaries: Vec<Summary>,
}

impl Registry for SyntheticRegistry {
    fn query(
        &mut self,
        dep: &Dependency,
        kind: QueryKind,
        f: &mut dyn FnMut(IndexSummary),
    ) -> Poll<CargoResult<()>> {
        for s in &self.summaries {
            let matched = match kind {
                QueryKind::Exact => dep.matches(s),
                QueryKind::RejectedVersions => dep.matches(s),
                QueryKind::AlternativeNames | QueryKind::Normalized => true,
            };
            if matched {
                f(IndexSummary::Candidate(s.clone()));
            }
        }
        Poll::Ready(Ok(()))
    }

    fn describe_source(&self, _src: SourceId) -> String {
        String::from("synthetic")
    }

    fn is_replaced(&self, _src: SourceId) -> bool {
        false
    }
    
    fn block_until_ready(&mut self) -> CargoResult<()> {
        Ok(())
    }
}

fn do_resolve(registry: &mut SyntheticRegistry, root: Summary) -> CargoResult<()> {
    let gctx = GlobalContext::default().unwrap();
    let version_prefs = VersionPreferences::default();
    resolver::resolve(
        &[(root, ResolveOpts::everything())],
        &[],
        registry,
        &version_prefs,
        ResolveVersion::with_rust_version(None),
        Some(&gctx),
    )?;
    Ok(())
}

/// Linear chain: root -> a -> b -> c -> ... -> z
/// Each package has one version. Tests resolver overhead with no branching.
fn build_linear_chain(depth: usize) -> (SyntheticRegistry, Summary) {
    let mut summaries = Vec::new();
    // Build from leaf to root so dependencies are defined before dependents
    for i in (0..depth).rev() {
        let name = format!("pkg-{i}");
        let deps = if i < depth - 1 {
            vec![dep(&format!("pkg-{}", i + 1), "1.0")]
        } else {
            vec![]
        };
        summaries.push(summary(&name, "1.0.0", deps));
    }

    let root = summary("root", "1.0.0", vec![dep("pkg-0", "1.0")]);
    (SyntheticRegistry { summaries }, root)
}

/// Wide fan: root depends on N independent packages, each with M versions.
/// Tests registry query throughput and version selection.
fn build_wide_fan(n_packages: usize, n_versions: usize) -> (SyntheticRegistry, Summary) {
    let mut summaries = Vec::new();
    let mut root_deps = Vec::new();

    for i in 0..n_packages {
        let name = format!("pkg-{i}");
        root_deps.push(dep(&name, "*"));
        for v in 0..n_versions {
            summaries.push(summary(&name, &format!("{v}.0.0"), vec![]));
        }
    }

    let root = summary("root", "1.0.0", root_deps);
    (SyntheticRegistry { summaries }, root)
}

/// Diamond: root -> {a, b}, a -> shared, b -> shared
/// Repeated N times wide. Tests conflict detection and shared dependency handling.
fn build_diamond(n_diamonds: usize) -> (SyntheticRegistry, Summary) {
    let mut summaries = Vec::new();
    let mut root_deps = Vec::new();

    for i in 0..n_diamonds {
        let shared = format!("shared-{i}");
        let left = format!("left-{i}");
        let right = format!("right-{i}");

        summaries.push(summary(&shared, "1.0.0", vec![]));
        summaries.push(summary(&left, "1.0.0", vec![dep(&shared, "1.0")]));
        summaries.push(summary(&right, "1.0.0", vec![dep(&shared, "1.0")]));

        root_deps.push(dep(&left, "1.0"));
        root_deps.push(dep(&right, "1.0"));
    }

    let root = summary("root", "1.0.0", root_deps);
    (SyntheticRegistry { summaries }, root)
}

fn resolve_linear_chain(c: &mut Criterion) {
    let mut group = c.benchmark_group("resolve_core/linear_chain");
    for depth in [10, 50, 200] {
        let (mut registry, root) = build_linear_chain(depth);
        group.bench_function(format!("depth_{depth}"), |b| {
            b.iter(|| do_resolve(&mut registry, root.clone()).unwrap())
        });
    }
    group.finish();
}

fn resolve_wide_fan(c: &mut Criterion) {
    let mut group = c.benchmark_group("resolve_core/wide_fan");
    for (n_packages, n_versions) in [(10, 5), (50, 5), (100, 10)] {
        let (mut registry, root) = build_wide_fan(n_packages, n_versions);
        group.bench_function(format!("{n_packages}pkg_{n_versions}ver"), |b| {
            b.iter(|| do_resolve(&mut registry, root.clone()).unwrap())
        });
    }
    group.finish();
}

fn resolve_diamond(c: &mut Criterion) {
    let mut group = c.benchmark_group("resolve_core/diamond");
    for n_diamonds in [5, 20, 50] {
        let (mut registry, root) = build_diamond(n_diamonds);
        group.bench_function(format!("{n_diamonds}_diamonds"), |b| {
            b.iter(|| do_resolve(&mut registry, root.clone()).unwrap())
        });
    }
    group.finish();
}

criterion_group!(benches, resolve_linear_chain, resolve_wide_fan, resolve_diamond);
criterion_main!(benches);
