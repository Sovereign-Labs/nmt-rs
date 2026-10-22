//! Rust counterparts of the Go benchmarks in celestiaorg/nmt (`nmt_test.go`).
//!
//! Group and benchmark names, tree sizes, namespace sizes, and leaf sizes match the Go
//! versions, so results can be compared with `go test -bench . -run '^$'` directly.
//! Go pushes `namespace || data` and hashes `0x00 || namespace || data`; here the namespace
//! is passed separately, but the hashed bytes are identical.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion, SamplingMode};
use nmt_rs::{
    NamespaceId, NamespaceMerkleHasher, NamespaceMerkleTree, NamespacedHash, NamespacedSha2Hasher,
};

type Nmt<const NS: usize> = NamespaceMerkleTree<NamespacedSha2Hasher<NS>, NS>;

type Leaves<const NS: usize> = Vec<(NamespaceId<NS>, Vec<u8>)>;

/// Minimal deterministic PRNG (splitmix64), standing in for Go's `crypto/rand`.
struct Rng(u64);

impl Rng {
    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^= z >> 31;
            chunk.copy_from_slice(&z.to_le_bytes()[..chunk.len()]);
        }
    }
}

/// Mirrors Go's `generateRandNamespacedRawData`: random namespaces, sorted, with random data.
fn rand_namespaced_leaves<const NS: usize>(total: usize, data_size: usize) -> Leaves<NS> {
    let mut rng = Rng(42);
    let mut namespaces: Vec<_> = (0..total)
        .map(|_| {
            let mut ns = NamespaceId([0; NS]);
            rng.fill(&mut ns.0);
            ns
        })
        .collect();
    namespaces.sort();
    namespaces
        .into_iter()
        .map(|ns| {
            let mut data = vec![0; data_size];
            rng.fill(&mut data);
            (ns, data)
        })
        .collect()
}

/// Same defaults as Go's `nmt.New`: sha256, max namespace ignored.
fn compute_root<const NS: usize>(leaves: &Leaves<NS>) -> NamespacedHash<NS> {
    let mut tree = Nmt::<NS>::with_hasher(NamespacedSha2Hasher::with_ignore_max_ns(true));
    for (ns, data) in leaves {
        tree.push_leaf(data, *ns).unwrap();
    }
    tree.root()
}

/// `BenchmarkComputeRoot`
fn bench_compute_root(c: &mut Criterion) {
    let mut group = c.benchmark_group("ComputeRoot");
    // Flat sampling keeps the 20k-leaf case from taking minutes.
    group.sampling_mode(SamplingMode::Flat);

    for (num_leaves, data_size) in [(64, 256), (128, 256), (256, 256), (20_000, 512)] {
        let leaves = rand_namespaced_leaves::<8>(num_leaves, data_size);
        let name = match num_leaves {
            20_000 => "20k-leaves".to_string(),
            n => format!("{n}-leaves"),
        };
        group.bench_function(name, |b| b.iter(|| compute_root(black_box(&leaves))));
    }
    group.finish();
}

/// `BenchmarkNMTReuseVsNoReuse`, `-Root-NoReuse` cases only: nmt-rs has no equivalent of
/// Go's `Reset`/`ReuseBuffers`, so there is no `-Root-ReuseTree` counterpart.
fn bench_nmt_no_reuse(c: &mut Criterion) {
    let mut group = c.benchmark_group("NMTReuseVsNoReuse");
    for num_leaves in [128, 256, 512, 1024, 2048] {
        let leaves = rand_namespaced_leaves::<29>(num_leaves, 512);
        group.bench_function(format!("{num_leaves}-leaves-Root-NoReuse"), |b| {
            b.iter(|| compute_root(black_box(&leaves)))
        });
    }
    group.finish();
}

criterion_group!(go_parity, bench_compute_root, bench_nmt_no_reuse);
criterion_main!(go_parity);
