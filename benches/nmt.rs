use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use nmt_rs::{
    simple_merkle::tree::MerkleTree, CelestiaNmt, NamespaceId, NamespaceMerkleHasher,
    NamespacedSha2Hasher, TmSha2Hasher,
};

/// Size of a Celestia share, used as the leaf size.
const SHARE_SIZE: usize = 512;
const NS_ID_SIZE: usize = 29;
/// Every namespace present in the tree holds this many consecutive leaves.
const LEAVES_PER_NS: usize = 4;
const TREE_SIZES: [usize; 3] = [64, 256, 1024];

type TmMerkleTree = MerkleTree<TmSha2Hasher>;

fn ns(id: u64) -> NamespaceId<NS_ID_SIZE> {
    let mut namespace = NamespaceId::default();
    namespace.0[NS_ID_SIZE - 8..].copy_from_slice(&id.to_be_bytes());
    namespace
}

/// Namespace of leaf `idx`. Only even ids are used, so odd ids are absent
/// from the tree while still falling inside the root's namespace range.
fn leaf_ns(idx: usize) -> NamespaceId<NS_ID_SIZE> {
    ns(2 * (idx / LEAVES_PER_NS) as u64)
}

fn leaves(n: usize) -> Vec<Vec<u8>> {
    (0..n).map(|i| vec![i as u8; SHARE_SIZE]).collect()
}

fn celestia_tree(leaves: &[Vec<u8>]) -> CelestiaNmt {
    // Celestia treats the max namespace (parity shares) as a marker and ignores it.
    let mut tree = CelestiaNmt::with_hasher(NamespacedSha2Hasher::with_ignore_max_ns(true));
    for (i, leaf) in leaves.iter().enumerate() {
        tree.push_leaf(leaf, leaf_ns(i)).unwrap();
    }
    tree
}

/// Index of the first leaf of a namespace in the middle of the tree.
fn middle_ns_start(n: usize) -> usize {
    n / 2 / LEAVES_PER_NS * LEAVES_PER_NS
}

/// A present namespace in the middle of the tree, and an absent one right after it.
fn middle_namespaces(n: usize) -> (NamespaceId<NS_ID_SIZE>, NamespaceId<NS_ID_SIZE>) {
    let id = 2 * (middle_ns_start(n) / LEAVES_PER_NS) as u64;
    (ns(id), ns(id + 1))
}

fn nmt_build_root(c: &mut Criterion) {
    let mut group = c.benchmark_group("nmt/build_root");
    for n in TREE_SIZES {
        let leaves = leaves(n);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &leaves, |b, leaves| {
            b.iter(|| celestia_tree(black_box(leaves)).root())
        });
    }
    group.finish();
}

fn nmt_namespace_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("nmt/namespace_proof");
    for n in TREE_SIZES {
        let mut tree = celestia_tree(&leaves(n));
        let (present, absent) = middle_namespaces(n);
        // Cache the root so only proof construction is measured.
        tree.root();

        group.bench_function(BenchmarkId::new("presence", n), |b| {
            b.iter(|| tree.get_namespace_proof(black_box(present)))
        });
        group.bench_function(BenchmarkId::new("absence", n), |b| {
            b.iter(|| tree.get_namespace_proof(black_box(absent)))
        });
    }
    group.finish();
}

fn nmt_verify_namespace(c: &mut Criterion) {
    let mut group = c.benchmark_group("nmt/verify_namespace");
    for n in TREE_SIZES {
        let mut tree = celestia_tree(&leaves(n));
        let root = tree.root();
        let (present, absent) = middle_namespaces(n);
        let (present_leaves, present_proof) = tree.get_namespace_with_proof(present);
        let (absent_leaves, absent_proof) = tree.get_namespace_with_proof(absent);

        group.bench_function(BenchmarkId::new("presence", n), |b| {
            b.iter(|| {
                present_proof
                    .verify_complete_namespace(black_box(&root), &present_leaves, present)
                    .unwrap()
            })
        });
        group.bench_function(BenchmarkId::new("absence", n), |b| {
            b.iter(|| {
                absent_proof
                    .verify_complete_namespace(black_box(&root), &absent_leaves, absent)
                    .unwrap()
            })
        });
    }
    group.finish();
}

fn nmt_verify_range(c: &mut Criterion) {
    let mut group = c.benchmark_group("nmt/verify_range");
    for n in TREE_SIZES {
        let mut tree = celestia_tree(&leaves(n));
        let root = tree.root();
        let start = middle_ns_start(n);
        // A partial range strictly inside a single namespace.
        let (range_leaves, proof) = tree.get_range_with_proof(start + 1..start + 3);
        let namespace = leaf_ns(start);

        group.bench_function(BenchmarkId::from_parameter(n), |b| {
            b.iter(|| {
                proof
                    .verify_range(black_box(&root), &range_leaves, namespace)
                    .unwrap()
            })
        });
    }
    group.finish();
}

fn nmt_narrow_range(c: &mut Criterion) {
    let mut group = c.benchmark_group("nmt/narrow_range");
    for n in TREE_SIZES {
        let mut tree = celestia_tree(&leaves(n));
        let namespace = leaf_ns(middle_ns_start(n));
        let (ns_leaves, proof) = tree.get_namespace_with_proof(namespace);
        // Drop one leaf from each side of the namespace.
        let left = &ns_leaves[..1];
        let right = &ns_leaves[ns_leaves.len() - 1..];

        group.bench_function(BenchmarkId::from_parameter(n), |b| {
            b.iter(|| {
                proof
                    .narrow_range(black_box(left), black_box(right), namespace)
                    .unwrap()
            })
        });
    }
    group.finish();
}

fn merkle_build_root(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle/build_root");
    for n in TREE_SIZES {
        let leaves = leaves(n);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &leaves, |b, leaves| {
            b.iter(|| {
                let mut tree = TmMerkleTree::new();
                for leaf in black_box(leaves) {
                    tree.push_raw_leaf(leaf);
                }
                tree.root()
            })
        });
    }
    group.finish();
}

fn merkle_verify_range(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle/verify_range");
    for n in TREE_SIZES {
        let mut tree = TmMerkleTree::new();
        for leaf in leaves(n) {
            tree.push_raw_leaf(&leaf);
        }
        let root = tree.root();
        let idx = n / 2;
        let proof = tree.build_range_proof(idx..idx + 1);
        let leaf_hashes = [*tree.leaves()[idx].hash()];

        group.bench_function(BenchmarkId::from_parameter(n), |b| {
            b.iter(|| proof.verify_range(black_box(&root), &leaf_hashes).unwrap())
        });
    }
    group.finish();
}

criterion_group!(
    nmt,
    nmt_build_root,
    nmt_namespace_proof,
    nmt_verify_namespace,
    nmt_verify_range,
    nmt_narrow_range
);
criterion_group!(merkle, merkle_build_root, merkle_verify_range);
criterion_main!(nmt, merkle);
