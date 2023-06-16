// #![feature(slice_take)]

use std::{collections::HashMap, ops::Range};

pub use nmt_proof::NamespaceProof;
use simple_merkle::{
    db::{LeafWithHash, MemDb, PreimageDb},
    error::RangeProofError,
    proof::Proof,
    tree::{MerkleHash, MerkleTree},
    utils::compute_num_left_siblings,
};

mod namespaced_hash;
pub use namespaced_hash::*;

// pub mod db;
pub mod nmt_proof;
pub mod simple_merkle;

pub type CelestiaNmt = NamespaceMerkleTree<MemDb<NamespacedHash>, NamespacedSha2Hasher>;

// /// Compute the number of left siblings required for an inclusion proof of the node at the provided index
// fn compute_num_left_siblings(node_idx: usize) -> usize {
//     // The number of left siblings needed is the same as the number of ones in the binary
//     // decomposition of the start index
//     let mut num_left_siblings = 0;
//     let mut start_idx = node_idx;
//     while start_idx != 0 {
//         if start_idx & 1 != 0 {
//             num_left_siblings += 1;
//         }
//         start_idx >>= 1;
//     }
//     num_left_siblings
// }

/// Checks if a proof contains any partial namespaces
fn check_proof_completeness(
    leaves: &[NamespacedHash],
    proof: &Vec<NamespacedHash>,
    num_left_siblings: usize,
) -> RangeProofType {
    // Check if the proof is complete
    let mut proof_type = RangeProofType::Complete;

    if num_left_siblings != 0 {
        let rightmost_left_sibling = &proof[num_left_siblings - 1];
        if rightmost_left_sibling.max_namespace() >= leaves[0].min_namespace() {
            proof_type = RangeProofType::Partial
        }
    }

    let num_right_siblings = proof.len() - num_left_siblings;
    if num_right_siblings != 0 {
        let leftmost_right_sibling = &proof[num_left_siblings];
        if leftmost_right_sibling.min_namespace()
            <= leaves
                .last()
                .expect("leaves has already been checked to be non-empty")
                .max_namespace()
        {
            proof_type = RangeProofType::Partial
        }
    }

    proof_type
}

// // Reconstruct the size of the tree.
// // This trick works by interpreting the binary representation of the index of a node as a *path*
// // to the node. If the lsb of the (remaining) path is a 1, turn right. Otherwise, turn left.
// fn compute_tree_size(
//     num_right_siblings: usize,
//     index_of_last_included_leaf: usize,
// ) -> Result<usize, RangeProofError> {
//     // Each right sibling converts a left turn into a right turn - replacing a
//     // zero in the path with a one.
//     let mut index_of_final_node = index_of_last_included_leaf;
//     let mut mask = 1;
//     let mut remaining_right_siblings = num_right_siblings;
//     while remaining_right_siblings > 0 {
//         if index_of_final_node & mask == 0 {
//             index_of_final_node |= mask;
//             remaining_right_siblings -= 1;
//         }
//         mask <<= 1;
//         // Ensure that the next iteration won't overflow on 32 bit platforms
//         if index_of_final_node == u32::MAX as usize {
//             return Err(RangeProofError::TreeTooLarge);
//         }
//     }
//     Ok(index_of_final_node + 1)
// }

pub struct NamespaceMerkleTree<Db, M: MerkleHash> {
    namespace_ranges: HashMap<NamespaceId, Range<usize>>,
    highest_ns: NamespaceId,
    ignore_max_ns: bool,
    inner: MerkleTree<Db, M>,
}

impl<Db, M: NamespaceMerkleHasher<Output = NamespacedHash>> NamespaceMerkleTree<Db, M>
where
    Db: PreimageDb<M::Output>,
{
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_hasher(hasher: M) -> Self {
        Self {
            namespace_ranges: Default::default(),
            highest_ns: NamespaceId([0u8; NAMESPACE_ID_LEN]),
            ignore_max_ns: hasher.ignores_max_ns(),
            inner: MerkleTree::<Db, M>::with_hasher(hasher),
        }
    }

    pub fn push_leaf(
        &mut self,
        raw_data: &[u8],
        namespace: NamespaceId,
    ) -> Result<(), &'static str> {
        let hash = NamespacedHash::hash_leaf(raw_data, namespace);
        // Force leaves to be pushed in order
        if namespace < self.highest_ns {
            return Err("Leaves' namespaces should be inserted in ascending order");
        }
        self.highest_ns = namespace;
        self.inner
            .push_leaf_with_hash_unchecked(raw_data.to_vec(), hash);

        let leaves_len = self.leaves().len();
        match self.namespace_ranges.entry(namespace) {
            std::collections::hash_map::Entry::Occupied(entry) => {
                entry.into_mut().end = leaves_len;
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(leaves_len - 1..leaves_len);
            }
        }
        Ok(())
    }

    pub fn root(&mut self) -> NamespacedHash {
        self.inner.root()
    }

    /// Checks a given range proof
    fn check_range_proof(
        &self,
        root: &NamespacedHash,
        leaves: &[NamespacedHash],
        proof: &mut Vec<NamespacedHash>,
        leaves_start_idx: usize,
    ) -> Result<RangeProofType, RangeProofError> {
        // As an optimization, the internal call doesn't recurse into subtrees of size smaller than 2
        // so we need to ensure that the root has size 2 or greater.
        match leaves.len() {
            0 => {
                if root == &NamespacedHash::empty() && proof.is_empty() {
                    return Ok(RangeProofType::Complete);
                }
                return Err(RangeProofError::NoLeavesProvided);
            }
            1 => {
                if proof.is_empty() {
                    if &leaves[0] == root && leaves_start_idx == 0 {
                        return Ok(RangeProofType::Complete);
                    }
                    return Err(RangeProofError::TreeDoesNotContainLeaf);
                }
            }
            _ => {}
        };

        // Check that the leaf hashes are well-formed
        for hash in proof.iter() {
            if hash.min_namespace() > hash.max_namespace() {
                return Err(RangeProofError::MalformedTree);
            }
        }

        let num_left_siblings = compute_num_left_siblings(leaves_start_idx);

        let proof_completeness = check_proof_completeness(leaves, proof, num_left_siblings);

        self.inner
            .check_range_proof(root, leaves, proof, leaves_start_idx)?;

        Ok(proof_completeness)
    }

    /// Creates a range proof providing the sibling hashes required to show that a set of values really does occur in
    /// the merkle tree at some half-open range of indices. Intermediate hashes are identified by an in-order traversal
    /// and are returned in that same order. Panics if the range to prove is larger than the tree's leaf array.
    ///
    /// Example: consider the following merkle tree with leaves [C, D, E, F]
    ///```ascii
    ///          root
    ///        /      \
    ///       A        B
    ///      / \      /  \
    ///     C   D    E    F
    ///
    /// ```
    ///
    /// A range proof of build_range_proof(1..3) would return the vector [C, F], since those two hashes, together
    /// with the two leaves in the range, are sufficient to reconstruct the tree
    pub fn build_range_proof(&mut self, leaf_range: Range<usize>) -> Proof<M> {
        self.inner.build_range_proof(leaf_range)
    }

    pub fn get_range_with_proof(
        &mut self,
        leaf_range: Range<usize>,
    ) -> (Vec<Vec<u8>>, NamespaceProof<M>) {
        let (leaves, proof) = self.inner.get_range_with_proof(leaf_range);
        (
            leaves,
            NamespaceProof::PresenceProof {
                proof,
                ignore_max_ns: self.ignore_max_ns,
            },
        )
    }

    pub fn get_index_with_proof(&mut self, idx: usize) -> (Vec<u8>, Proof<M>) {
        self.inner.get_index_with_proof(idx)
    }

    pub fn get_namespace_with_proof(
        &mut self,
        namespace: NamespaceId,
    ) -> (Vec<Vec<u8>>, NamespaceProof<M>) {
        let leaf_range = if let Some(range) = self.namespace_ranges.get(&namespace) {
            range.clone()
        } else {
            0..0
        };
        let leaves = self.inner.get_leaves(leaf_range);

        (leaves, self.get_namespace_proof(namespace))
    }

    pub fn leaves(&self) -> &[LeafWithHash<NamespacedHash>] {
        self.inner.leaves()
    }

    pub fn get_namespace_proof(&mut self, namespace: NamespaceId) -> NamespaceProof<M> {
        // If the namespace is outside the range covered by the root, we're done
        if !self.root().contains(namespace) {
            return NamespaceProof::AbsenceProof {
                proof: Default::default(),
                ignore_max_ns: self.ignore_max_ns,
                leaf: None,
            };
        }

        // If the namespace has data, just look up that namespace range and prove it by index
        if let Some(leaf_range) = self.namespace_ranges.get(&namespace) {
            return NamespaceProof::PresenceProof {
                proof: self.inner.build_range_proof(leaf_range.clone()),
                ignore_max_ns: self.ignore_max_ns,
            };
        }

        // Otherwise, the namespace is within the range covered by the tree, but doesn't actually exist.
        // To prove this, we can prove that for some index `i`, leaves[i].namespace() < namespace < leaves[i+1].namespace().
        // Since a range proof for the range [i, i+1) includes the namespaced hash of leaf i+1,
        // proving this range is sufficient to establish that the namespace doesn't exist.
        let namespace = self
            .inner
            .leaves()
            .binary_search_by(|l| l.hash.min_namespace().cmp(&namespace));

        // The builtin binary search method returns the index where the item could be inserted while maintaining sorted order,
        // which is the index after the leaf we want to prove
        let idx =
            namespace.expect_err("tree cannot contain leaf with namespace that does not exist") - 1;

        let proof = self.build_range_proof(idx..idx + 1);

        let mut proof = NamespaceProof::PresenceProof {
            proof,
            ignore_max_ns: self.ignore_max_ns,
        };
        proof.convert_to_absence_proof(self.inner.leaves()[idx].hash.clone());
        proof
    }

    fn verify_namespace(
        &self,
        root: &NamespacedHash,
        raw_leaves: &[impl AsRef<[u8]>],
        namespace: NamespaceId,
        proof: NamespaceProof<M>,
    ) -> Result<(), RangeProofError> {
        if root.is_empty_root() && raw_leaves.is_empty() {
            return Ok(());
        }

        match proof {
            NamespaceProof::AbsenceProof {
                proof:
                    Proof {
                        mut siblings,
                        start_idx,
                    },
                ignore_max_ns: _,
                leaf,
            } => {
                if !root.contains(namespace) {
                    return Ok(());
                }
                let leaf = leaf.ok_or(RangeProofError::MalformedProof)?;
                // Check that they haven't provided an absence proof for a non-empty namespace
                if !raw_leaves.is_empty() {
                    return Err(RangeProofError::MalformedProof);
                }
                // Check that the provided leaf actually precedes the namespace
                if leaf.max_namespace() >= namespace {
                    return Err(RangeProofError::MalformedProof);
                }
                let num_left_siblings = compute_num_left_siblings(start_idx as usize);

                // Check that the closest sibling actually follows the namespace
                if siblings.len() > num_left_siblings {
                    let leftmost_right_sibling = &siblings[num_left_siblings];
                    if leftmost_right_sibling.min_namespace() <= namespace {
                        return Err(RangeProofError::MalformedProof);
                    }
                }
                // Then, check that the root is real
                self.inner
                    .check_range_proof(root, &[leaf], &mut siblings, start_idx as usize)?;
            }
            NamespaceProof::PresenceProof {
                proof:
                    Proof {
                        mut siblings,
                        start_idx,
                    },
                ignore_max_ns: _,
            } => {
                if !root.contains(namespace) {
                    return Err(RangeProofError::TreeDoesNotContainLeaf);
                }
                let leaf_hashes: Vec<NamespacedHash> = raw_leaves
                    .iter()
                    .map(|data| NamespacedHash::hash_leaf(data.as_ref(), namespace))
                    .collect();
                if let RangeProofType::Partial =
                    self.check_range_proof(root, &leaf_hashes, &mut siblings, start_idx as usize)?
                {
                    return Err(RangeProofError::MissingLeaf);
                }
            }
        }
        Ok(())
    }
}

impl<Db: PreimageDb<M::Output>, M: MerkleHash> Default for NamespaceMerkleTree<Db, M> {
    fn default() -> Self {
        Self {
            namespace_ranges: Default::default(),
            highest_ns: NamespaceId::default(),
            ignore_max_ns: true,
            inner: Default::default(),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum RangeProofType {
    /// A range proof over a single namespace is complete if it includes all the leaves
    /// in that namespace. A range proof over several namespaces is complete if all
    /// individual namespaces are complete.
    Complete,
    /// A range proof over a single namespace is partial if it omits at least one leaf from that namespace.
    /// A range proof over several namespaces is partial if it includes at least one namespace that is partial.
    ///
    /// Note that (since ranges are contiguous) only the first or last namespace covered by a range proof may be partial.
    Partial,
}

#[cfg(test)]
mod tests {
    use crate::{
        namespaced_hash::{NamespaceId, NamespacedSha2Hasher},
        nmt_proof::NamespaceProof,
        simple_merkle::db::MemDb,
        NamespaceMerkleTree, NamespacedHash, RangeProofType, NAMESPACE_ID_LEN,
    };

    /// Builds a tree with N leaves
    fn tree_with_n_leaves(
        n: usize,
    ) -> NamespaceMerkleTree<MemDb<NamespacedHash>, NamespacedSha2Hasher> {
        let mut tree = NamespaceMerkleTree::<MemDb<NamespacedHash>, NamespacedSha2Hasher>::new();
        for x in 0..n {
            let namespace = crate::NamespaceId(((x + 1) as u64).to_be_bytes());
            let _ = tree.push_leaf(x.to_be_bytes().as_ref(), namespace);
        }
        tree
    }

    /// Builds a tree with n leaves, and then creates and checks proofs of all
    /// valid ranges.
    fn test_range_proof_roundtrip_with_n_leaves(n: usize) {
        let mut tree = tree_with_n_leaves(n);
        let root = tree.root();
        for i in 1..=n {
            for j in 0..=i {
                let proof = tree.build_range_proof(j..i);
                let leaf_hashes: Vec<NamespacedHash> =
                    tree.leaves()[j..i].iter().map(|l| l.hash.clone()).collect();
                let res =
                    tree.check_range_proof(&root, &leaf_hashes, &mut proof.take_siblings(), j);
                if i != j {
                    dbg!(i, j, &res);
                    println!("{:?}", &leaf_hashes);
                    assert!(res.is_ok());
                    assert!(res.unwrap() == RangeProofType::Complete)
                } else {
                    // Cannot prove the empty range!
                    assert!(res.is_err())
                }
            }
        }
        test_min_and_max_ns_against(&mut tree)
    }
    #[test]
    fn test_range_proof_roundtrip() {
        for x in 0..20 {
            test_range_proof_roundtrip_with_n_leaves(x)
        }
    }

    // Try building and checking a proof of the min namespace, and the max namespace.
    // Then, add a node to the max namespace and check the max again.
    fn test_min_and_max_ns_against(
        tree: &mut NamespaceMerkleTree<MemDb<NamespacedHash>, NamespacedSha2Hasher>,
    ) {
        let root = tree.root();
        let min_namespace = NamespaceId([0u8; NAMESPACE_ID_LEN]);
        let max_namespace = NamespaceId([0xffu8; NAMESPACE_ID_LEN]);
        let (leaves, proof) = tree.get_namespace_with_proof(min_namespace);
        assert!(proof
            .verify_complete_namespace(&root, &leaves, min_namespace)
            .is_ok());

        let (leaves, proof) = tree.get_namespace_with_proof(max_namespace);
        assert!(proof
            .verify_complete_namespace(&root, &leaves, max_namespace)
            .is_ok());

        tree.push_leaf(b"some_leaf", max_namespace)
            .expect("can always push max namespace");

        let root = tree.root();
        let (leaves, proof) = tree.get_namespace_with_proof(max_namespace);
        assert!(proof
            .verify_complete_namespace(&root, &leaves, max_namespace)
            .is_ok());
    }

    #[test]
    fn test_completeness_check() {
        // Build a tree with 32 leaves spread evenly across 8 namespaces
        let mut tree = NamespaceMerkleTree::<MemDb<NamespacedHash>, NamespacedSha2Hasher>::new();
        for x in 0..32 {
            let namespace = crate::NamespaceId((x / 4_u64).to_be_bytes());
            let _ = tree.push_leaf(x.to_be_bytes().as_ref(), namespace);
        }
        let root = tree.root();
        let leaf_hashes: Vec<NamespacedHash> =
            tree.leaves().iter().map(|x| x.hash.clone()).collect();

        // For each potential range of size four, build and check a range proof
        for i in 0..=28 {
            let leaf_range = i..i + 4;
            let proof = tree.build_range_proof(leaf_range.clone());

            let result = tree.check_range_proof(
                &root,
                &leaf_hashes[leaf_range],
                &mut proof.take_siblings(),
                i,
            );
            assert!(result.is_ok());

            // We've set up our tree to have four leaves in each namespace, so a
            // range of leaves covers a complete namespace only if and only if the start index
            // is divisible by four
            let should_be_complete = (i % 4) == 0;
            if should_be_complete {
                assert_eq!(result, Ok(RangeProofType::Complete))
            } else {
                assert_eq!(result, Ok(RangeProofType::Partial))
            }
        }
        for nid in 0..100u64 {
            let namespace = NamespaceId(nid.to_be_bytes());
            let (leaves, proof) = tree.get_namespace_with_proof(namespace);
            println!("Poof: {:?}", &proof);

            let pf = proof.verify_complete_namespace(&root, &leaves, namespace);
            if pf.is_err() {
                dbg!(&pf, namespace);
                println!("{:?}", &leaves);
            }
            assert!(pf.is_ok());
        }
    }
    #[test]
    fn test_namespace_verification() {
        let mut tree = NamespaceMerkleTree::<MemDb<NamespacedHash>, NamespacedSha2Hasher>::new();
        // Put a bunch of data in the tree
        for x in 0..33 {
            // Ensure that some namespaces are skipped, including the zero namespace
            let namespace = crate::NamespaceId((((x / 5_u64) * 3) + 1).to_be_bytes());
            let _ = tree.push_leaf(x.to_be_bytes().as_ref(), namespace);
        }
        let root = tree.root();
        let raw_leaves: Vec<Vec<u8>> = tree.leaves().iter().map(|x| x.data.clone()).collect();

        // Build proofs for each range that's actually included, and check that the range can be retrieved correctly
        for (namespace, range) in tree.namespace_ranges.clone().iter() {
            let proof = tree.build_range_proof(range.clone());
            assert!(!range.is_empty());

            let proof = NamespaceProof::PresenceProof {
                proof,
                ignore_max_ns: true,
            };

            assert!(tree
                .verify_namespace(&root, &raw_leaves[range.clone()], *namespace, proof)
                .is_ok());
        }

        // Build and check proofs for a bunch of namespaces, including some that are present and some that are absent.
        for nid in 0..100u64 {
            let namespace = NamespaceId(nid.to_be_bytes());
            let (leaves, proof) = tree.get_namespace_with_proof(namespace);
            println!("Poof: {:?}", &proof);

            let pf = proof.verify_complete_namespace(&root, &leaves, namespace);
            if pf.is_err() {
                dbg!(&pf, namespace);
                println!("{:?}", &leaves);
            }
            assert!(pf.is_ok());
        }

        test_min_and_max_ns_against(&mut tree)
    }
}
