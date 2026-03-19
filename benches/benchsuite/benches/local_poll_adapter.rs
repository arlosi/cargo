use cargo::util::LocalPollAdapter;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use std::rc::Rc;
use std::task::Poll;

struct Registry {
    data: Vec<(String, Vec<u32>)>,
}

impl Registry {
    fn new(n_packages: usize, n_versions: usize) -> Self {
        let data = (0..n_packages)
            .map(|i| {
                let name = format!("package-{i}");
                let versions: Vec<u32> = (0..n_versions).map(|v| v as u32).collect();
                (name, versions)
            })
            .collect();
        Self { data }
    }

    /// Simulate a synchronous registry query (completes immediately, no await yield).
    async fn query(&self, key: &String) -> Result<Vec<u32>, anyhow::Error> {
        match self.data.iter().find(|(name, _)| name == key) {
            Some((_, versions)) => Ok(versions.clone()),
            None => Err(anyhow::anyhow!("package not found: {key}")),
        }
    }
}

/// Benchmark polling immediate (non-yielding) async results through LocalPollAdapter.
/// This is the hot path in the resolver: registry queries that complete synchronously
/// because index data is already cached on disk.
fn poll_immediate(c: &mut Criterion) {
    let mut group = c.benchmark_group("local_poll_adapter/immediate");

    for n_packages in [10, 100, 1000] {
        group.bench_function(format!("{n_packages}_packages"), |b| {
            let registry = Rc::new(Registry::new(n_packages, 5));
            let keys: Vec<String> = (0..n_packages).map(|i| format!("package-{i}")).collect();
            b.iter_batched(
                || LocalPollAdapter::new(registry.clone()),
                |mut adapter| {
                    for key in &keys {
                        let result = adapter.poll(Registry::query, key.clone());
                        assert!(matches!(result, Poll::Ready(Ok(_))));
                    }
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

/// Benchmark cache hits: once a result is polled, subsequent polls for the same
/// key should return the cached value cheaply.
fn poll_cached(c: &mut Criterion) {
    let mut group = c.benchmark_group("local_poll_adapter/cached");

    for n_lookups in [10, 100, 1000] {
        group.bench_function(format!("{n_lookups}_lookups"), |b| {
            let registry = Rc::new(Registry::new(100, 5));
            b.iter_batched(
                || {
                    let mut adapter = LocalPollAdapter::new(registry.clone());
                    // Pre-populate cache
                    for i in 0..100 {
                        let key = format!("package-{i}");
                        let _ = adapter.poll(Registry::query, key);
                    }
                    adapter
                },
                |mut adapter| {
                    // All lookups hit the cache
                    for i in 0..n_lookups {
                        let key = format!("package-{}", i % 100);
                        let result = adapter.poll(Registry::query, key);
                        assert!(matches!(result, Poll::Ready(Ok(_))));
                    }
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

criterion_group!(benches, poll_immediate, poll_cached);
criterion_main!(benches);
