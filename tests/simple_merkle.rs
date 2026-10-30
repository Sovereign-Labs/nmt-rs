//! Range proofs over the plain (non-namespaced) merkle tree, using the Tendermint hasher.

use nmt_rs::{
    simple_merkle::{
        db::MemDb,
        error::RangeProofError,
        proof::Proof,
        tree::{MerkleHash, MerkleTree},
    },
    TmSha2Hasher,
};
use sha2::Sha256;
use tendermint::merkle::simple_hash_from_byte_vectors;

type TmTree = MerkleTree<MemDb<[u8; 32]>, TmSha2Hasher>;

fn leaf_data(n: usize) -> Vec<Vec<u8>> {
    (0..n).map(|i| format!("leaf_{i}").into_bytes()).collect()
}

fn tree_with_leaves(leaves: &[Vec<u8>]) -> TmTree {
    let mut tree = TmTree::new();
    for leaf in leaves {
        tree.push_raw_leaf(leaf);
    }
    tree
}

fn leaf_hashes(leaves: &[Vec<u8>]) -> Vec<[u8; 32]> {
    leaves
        .iter()
        .map(|leaf| TmSha2Hasher::new().hash_leaf(leaf))
        .collect()
}

#[test]
fn root_matches_tendermint() {
    for n in 0..=33 {
        let leaves = leaf_data(n);
        let mut tree = tree_with_leaves(&leaves);
        assert_eq!(
            tree.root(),
            simple_hash_from_byte_vectors::<Sha256>(&leaves),
            "{n} leaves"
        );
    }
}

#[test]
fn range_proof_roundtrip() {
    for n in 1..=16 {
        let leaves = leaf_data(n);
        let hashes = leaf_hashes(&leaves);
        let mut tree = tree_with_leaves(&leaves);
        let root = tree.root();
        for start in 0..n {
            for end in start + 1..=n {
                let (data, proof) = tree.get_range_with_proof(start..end);
                assert_eq!(data, &leaves[start..end]);
                assert_eq!(proof, tree.build_range_proof(start..end));
                proof.verify_range(&root, &hashes[start..end]).unwrap();
                proof
                    .verify_range_with_hasher(&root, &hashes[start..end], TmSha2Hasher::new())
                    .unwrap();
            }
        }
    }
}

#[test]
fn range_proof_rejects_wrong_amount_of_leaves() {
    let leaves = leaf_data(8);
    let hashes = leaf_hashes(&leaves);
    let mut tree = tree_with_leaves(&leaves);
    let root = tree.root();
    let proof = tree.build_range_proof(2..5);

    for wrong in [&hashes[2..4], &hashes[2..6]] {
        assert_eq!(
            proof.verify_range(&root, wrong),
            Err(RangeProofError::WrongAmountOfLeavesProvided)
        );
        assert_eq!(
            proof.verify_range_with_hasher(&root, wrong, TmSha2Hasher::new()),
            Err(RangeProofError::WrongAmountOfLeavesProvided)
        );
    }
}

#[test]
fn single_leaf_tree_verifies_with_empty_proof() {
    let leaves = leaf_data(1);
    let hashes = leaf_hashes(&leaves);
    let mut tree = tree_with_leaves(&leaves);
    let root = tree.root();

    let (data, proof) = tree.get_index_with_proof(0);
    assert_eq!(data, leaves[0]);
    assert!(proof.siblings().is_empty());
    proof.verify_range(&root, &hashes).unwrap();

    // A single leaf can only be the root if it sits at index 0
    let shifted = Proof::<TmSha2Hasher> {
        siblings: vec![],
        range: 1..2,
    };
    assert_eq!(
        shifted.verify_range(&root, &hashes),
        Err(RangeProofError::TreeDoesNotContainLeaf)
    );
}

#[test]
fn narrowed_range_proofs_verify() {
    for n in 1..=12 {
        let leaves = leaf_data(n);
        let hashes = leaf_hashes(&leaves);
        let mut tree = tree_with_leaves(&leaves);
        let root = tree.root();
        for start in 0..n {
            for end in start + 1..=n {
                let proof = tree.build_range_proof(start..end);
                for new_start in start..end {
                    for new_end in new_start + 1..=end {
                        let narrowed = proof
                            .narrow_range_with_hasher(
                                &hashes[start..new_start],
                                &hashes[new_end..end],
                                TmSha2Hasher::new(),
                            )
                            .unwrap();
                        assert_eq!(narrowed.start_idx() as usize, new_start);
                        assert_eq!(narrowed.end_idx() as usize, new_end);
                        assert_eq!(narrowed, tree.build_range_proof(new_start..new_end));
                        narrowed
                            .verify_range(&root, &hashes[new_start..new_end])
                            .unwrap();
                    }
                }
            }
        }
    }
}

#[test]
fn narrowing_rejects_empty_or_oversized_ranges() {
    let leaves = leaf_data(8);
    let hashes = leaf_hashes(&leaves);
    let mut tree = tree_with_leaves(&leaves);
    let proof = tree.build_range_proof(2..5);

    assert_eq!(
        proof.narrow_range_with_hasher(&hashes[2..4], &hashes[4..5], TmSha2Hasher::new()),
        Err(RangeProofError::NoLeavesProvided)
    );
    assert_eq!(
        proof.narrow_range_with_hasher(&hashes[2..4], &hashes[4..6], TmSha2Hasher::new()),
        Err(RangeProofError::WrongAmountOfLeavesProvided)
    );
}

#[test]
fn proof_edge_siblings() {
    let leaves = leaf_data(8);
    let hashes = leaf_hashes(&leaves);
    let mut tree = tree_with_leaves(&leaves);

    let first = tree.build_range_proof(0..1);
    assert_eq!(first.rightmost_left_sibling(), None);
    assert_eq!(first.leftmost_right_sibling(), Some(&hashes[1]));

    let middle = tree.build_range_proof(3..5);
    assert_eq!(middle.rightmost_left_sibling(), Some(&hashes[2]));
    assert_eq!(middle.leftmost_right_sibling(), Some(&hashes[5]));

    let last = tree.build_range_proof(7..8);
    assert_eq!(last.rightmost_left_sibling(), Some(&hashes[6]));
    assert_eq!(last.leftmost_right_sibling(), None);
}

#[test]
#[should_panic(expected = "Index out of range")]
fn build_range_proof_panics_past_the_last_leaf() {
    let mut tree = tree_with_leaves(&leaf_data(4));
    tree.build_range_proof(2..5);
}
