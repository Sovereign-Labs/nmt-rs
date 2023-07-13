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

const CELESTIA_NS_ID_SIZE: usize = 29;
pub type CelestiaNmt = NamespaceMerkleTree<
    MemDb<NamespacedHash<CELESTIA_NS_ID_SIZE>>,
    NamespacedSha2Hasher<CELESTIA_NS_ID_SIZE>,
    CELESTIA_NS_ID_SIZE,
>;

/// Checks if a proof contains any partial namespaces
fn check_proof_completeness<const NS_ID_SIZE: usize>(
    leaves: &[NamespacedHash<NS_ID_SIZE>],
    proof: &[NamespacedHash<NS_ID_SIZE>],
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

pub struct NamespaceMerkleTree<Db, M: MerkleHash, const NS_ID_SIZE: usize> {
    namespace_ranges: HashMap<NamespaceId<NS_ID_SIZE>, Range<usize>>,
    highest_ns: NamespaceId<NS_ID_SIZE>,
    ignore_max_ns: bool,
    inner: MerkleTree<Db, M>,
}

impl<Db, M, const NS_ID_SIZE: usize> NamespaceMerkleTree<Db, M, NS_ID_SIZE>
where
    Db: PreimageDb<M::Output>,
    M: NamespaceMerkleHasher<Output = NamespacedHash<NS_ID_SIZE>>,
{
    pub fn new() -> Self {
        Default::default()
    }

    pub fn with_hasher(hasher: M) -> Self {
        Self {
            namespace_ranges: Default::default(),
            highest_ns: NamespaceId([0u8; NS_ID_SIZE]),
            ignore_max_ns: hasher.ignores_max_ns(),
            inner: MerkleTree::<Db, M>::with_hasher(hasher),
        }
    }

    pub fn push_leaf(
        &mut self,
        raw_data: &[u8],
        namespace: NamespaceId<NS_ID_SIZE>,
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

    pub fn root(&mut self) -> NamespacedHash<NS_ID_SIZE> {
        self.inner.root()
    }

    /// Checks a given range proof
    fn check_range_proof(
        &self,
        root: &NamespacedHash<NS_ID_SIZE>,
        leaves: &[NamespacedHash<NS_ID_SIZE>],
        proof: &[NamespacedHash<NS_ID_SIZE>],
        leaves_start_idx: usize,
    ) -> Result<RangeProofType, RangeProofError> {
        // As an optimization, the internal call doesn't recurse into subtrees of size smaller than 2
        // so we need to ensure that the root has size 2 or greater.
        match leaves.len() {
            0 => {
                if root == &NamespacedHash::EMPTY_ROOT && proof.is_empty() {
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
    /// ```ascii
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
    ) -> (Vec<Vec<u8>>, NamespaceProof<M, NS_ID_SIZE>) {
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
        namespace: NamespaceId<NS_ID_SIZE>,
    ) -> (Vec<Vec<u8>>, NamespaceProof<M, NS_ID_SIZE>) {
        let leaf_range = if let Some(range) = self.namespace_ranges.get(&namespace) {
            range.clone()
        } else {
            0..0
        };
        let leaves = self.inner.get_leaves(leaf_range);

        (leaves, self.get_namespace_proof(namespace))
    }

    pub fn leaves(&self) -> &[LeafWithHash<NamespacedHash<NS_ID_SIZE>>] {
        self.inner.leaves()
    }

    pub fn get_namespace_proof(
        &mut self,
        namespace: NamespaceId<NS_ID_SIZE>,
    ) -> NamespaceProof<M, NS_ID_SIZE> {
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
        // To prove this, we can prove that for some index `i`, leaves[i-1].namespace() < namespace < leaves[i].namespace().
        // Since a range proof for the range [i, i+1) includes the namespaced hash of the left sibling
        // of the leaf i, which must include the namespace of the leaf i-1, then
        // proving this range is sufficient to establish that the namespace doesn't exist.
        let namespace = self
            .inner
            .leaves()
            .binary_search_by(|l| l.hash.min_namespace().cmp(&namespace));

        // The builtin binary search method returns the index where the item could be inserted while maintaining sorted order,
        // which is the index of the leaf we want to prove
        let idx =
            namespace.expect_err("tree cannot contain leaf with namespace that does not exist");

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
        root: &NamespacedHash<NS_ID_SIZE>,
        raw_leaves: &[impl AsRef<[u8]>],
        namespace: NamespaceId<NS_ID_SIZE>,
        proof: &NamespaceProof<M, NS_ID_SIZE>,
    ) -> Result<(), RangeProofError> {
        if root.is_empty_root() && raw_leaves.is_empty() {
            return Ok(());
        }

        match proof {
            NamespaceProof::AbsenceProof { leaf, .. } => {
                if !root.contains(namespace) {
                    return Ok(());
                }
                let leaf = leaf.clone().ok_or(RangeProofError::MalformedProof)?;
                // Check that they haven't provided an absence proof for a non-empty namespace
                if !raw_leaves.is_empty() {
                    return Err(RangeProofError::MalformedProof);
                }
                // Check that the provided namespace actually precedes the leaf
                if namespace >= leaf.min_namespace() {
                    return Err(RangeProofError::MalformedProof);
                }
                let num_left_siblings = compute_num_left_siblings(proof.start_idx() as usize);

                // Check that the namespace actually follows the closest sibling
                let siblings = proof.siblings();
                if num_left_siblings > 0 {
                    let rightmost_left_sibling = &siblings[num_left_siblings - 1];
                    if rightmost_left_sibling.max_namespace() >= namespace {
                        return Err(RangeProofError::MalformedProof);
                    }
                }
                // Then, check that the root is real
                self.inner.check_range_proof(
                    root,
                    &[leaf],
                    proof.siblings(),
                    proof.start_idx() as usize,
                )?;
            }
            NamespaceProof::PresenceProof { .. } => {
                if !root.contains(namespace) {
                    return Err(RangeProofError::TreeDoesNotContainLeaf);
                }
                let leaf_hashes: Vec<NamespacedHash<NS_ID_SIZE>> = raw_leaves
                    .iter()
                    .map(|data| NamespacedHash::hash_leaf(data.as_ref(), namespace))
                    .collect();
                let proof_type = self.check_range_proof(
                    root,
                    &leaf_hashes,
                    proof.siblings(),
                    proof.start_idx() as usize,
                )?;
                if proof_type == RangeProofType::Partial {
                    return Err(RangeProofError::MissingLeaf);
                }
            }
        }
        Ok(())
    }
}

impl<Db, M, const NS_ID_SIZE: usize> Default for NamespaceMerkleTree<Db, M, NS_ID_SIZE>
where
    Db: PreimageDb<M::Output>,
    M: MerkleHash,
{
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
        NamespaceMerkleTree, NamespacedHash, RangeProofType, CELESTIA_NS_ID_SIZE,
    };

    type DefaultNmt<const NS_ID_SIZE: usize> = NamespaceMerkleTree<
        MemDb<NamespacedHash<NS_ID_SIZE>>,
        NamespacedSha2Hasher<NS_ID_SIZE>,
        NS_ID_SIZE,
    >;

    fn ns_id_from_u64<const NS_ID_SIZE: usize>(val: u64) -> NamespaceId<NS_ID_SIZE> {
        // make sure the namespace id can hold the provided value
        assert!(NS_ID_SIZE >= 8);
        let mut namespace = NamespaceId::default();
        namespace.0[NS_ID_SIZE - 8..].copy_from_slice(&val.to_be_bytes());
        namespace
    }

    /// Builds a tree from provided namespace ids
    fn tree_from_namespace_ids<const NS_ID_SIZE: usize>(
        ns_ids: impl AsRef<[u64]>,
    ) -> DefaultNmt<NS_ID_SIZE> {
        let mut tree = DefaultNmt::new();
        for (i, &ns_id) in ns_ids.as_ref().iter().enumerate() {
            let data = format!("leaf_{i}");
            let namespace = ns_id_from_u64(ns_id);
            tree.push_leaf(data.as_bytes(), namespace)
                .expect("Failed to push the leaf");
        }
        tree
    }

    /// Builds a tree with N leaves
    fn tree_with_n_leaves<const NS_ID_SIZE: usize>(n: usize) -> DefaultNmt<NS_ID_SIZE> {
        tree_from_namespace_ids((0..n as u64).collect::<Vec<_>>())
    }

    #[test]
    fn test_absence_proof_leaf_advances_the_namespace() {
        let mut tree = tree_from_namespace_ids::<8>(&[1, 2, 3, 4, 6, 7, 8, 9]);
        let namespace = ns_id_from_u64(5);
        let proof = tree.get_namespace_proof(namespace);
        let no_leaves: &[&[u8]] = &[];

        proof
            .verify_complete_namespace(&tree.root(), no_leaves, namespace)
            .unwrap();

        let NamespaceProof::AbsenceProof { leaf: Some(leaf), .. } = proof else {
            unreachable!();
        };

        // https://github.com/celestiaorg/nmt/blob/master/docs/spec/nmt.md#verification-of-nmt-absence-proof
        assert!(leaf.min_namespace() > namespace);
    }

    #[test]
    fn test_absence_proof_return_err_if_leaf_doesnt_follow_rightmost_left_sibling() {
        let mut tree = tree_from_namespace_ids::<8>(&[1, 2, 3, 4, 6, 7, 8, 9]);
        let namespace = ns_id_from_u64(5);
        let proof = tree.get_namespace_proof(namespace);
        let no_leaves: &[&[u8]] = &[];

        for i in [3, 4, 6, 7] {
            let mut proof = proof.clone();
            let NamespaceProof::AbsenceProof { leaf, .. } = &mut proof else {
                unreachable!();
            };
            let data = format!("leaf_{i}").as_bytes().to_vec();
            *leaf = Some(NamespacedHash::hash_leaf(&data, ns_id_from_u64(i)));
            proof
                .verify_complete_namespace(&tree.root(), no_leaves, ns_id_from_u64(2))
                .unwrap_err();
        }
    }

    #[test]
    fn test_absence_proof_doesnt_include_leaf_if_namespace_is_out_of_root_ns_range() {
        let mut tree = tree_from_namespace_ids::<8>(&[2, 3, 4, 5]);
        for namespace in [1, 6] {
            let namespace = ns_id_from_u64(namespace);
            let proof = tree.get_namespace_proof(namespace);

            proof
                .clone()
                .verify_complete_namespace(&tree.root(), &Vec::<Vec<u8>>::new(), namespace)
                .unwrap();

            assert!(matches!(
                proof,
                NamespaceProof::AbsenceProof { leaf: None, .. }
            ));
        }
    }

    /// Builds a tree with n leaves, and then creates and checks proofs of all
    /// valid ranges.
    fn test_range_proof_roundtrip_with_n_leaves<const NS_ID_SIZE: usize>(n: usize) {
        let mut tree = tree_with_n_leaves::<NS_ID_SIZE>(n);
        let root = tree.root();
        for i in 1..=n {
            for j in 0..=i {
                let proof = tree.build_range_proof(j..i);
                let leaf_hashes: Vec<_> =
                    tree.leaves()[j..i].iter().map(|l| l.hash.clone()).collect();
                let res = tree.check_range_proof(&root, &leaf_hashes, proof.siblings(), j);
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
            test_range_proof_roundtrip_with_n_leaves::<8>(x);
            test_range_proof_roundtrip_with_n_leaves::<17>(x);
            test_range_proof_roundtrip_with_n_leaves::<24>(x);
            test_range_proof_roundtrip_with_n_leaves::<CELESTIA_NS_ID_SIZE>(x);
            test_range_proof_roundtrip_with_n_leaves::<32>(x);
        }
    }

    fn test_completeness_check_impl<const NS_ID_SIZE: usize>() {
        // Build a tree with 32 leaves spread evenly across 8 namespaces
        let mut tree = DefaultNmt::<NS_ID_SIZE>::new();
        for x in 0..32 {
            let namespace = ns_id_from_u64(x / 4);
            let _ = tree.push_leaf(x.to_be_bytes().as_ref(), namespace);
        }
        let root = tree.root();
        let leaf_hashes: Vec<_> = tree.leaves().iter().map(|x| x.hash.clone()).collect();

        // For each potential range of size four, build and check a range proof
        for i in 0..=28 {
            let leaf_range = i..i + 4;
            let proof = tree.build_range_proof(leaf_range.clone());

            let result =
                tree.check_range_proof(&root, &leaf_hashes[leaf_range], proof.siblings(), i);
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
            let namespace = ns_id_from_u64(nid);
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
    fn test_completeness_check() {
        test_completeness_check_impl::<8>();
        test_completeness_check_impl::<17>();
        test_completeness_check_impl::<24>();
        test_completeness_check_impl::<CELESTIA_NS_ID_SIZE>();
        test_completeness_check_impl::<32>();
    }

    // Try building and checking a proof of the min namespace, and the max namespace.
    // Then, add a node to the max namespace and check the max again.
    fn test_min_and_max_ns_against<const NS_ID_SIZE: usize>(tree: &mut DefaultNmt<NS_ID_SIZE>) {
        let root = tree.root();
        let min_namespace = NamespaceId([0; NS_ID_SIZE]);
        let max_namespace = NamespaceId([0xff; NS_ID_SIZE]);
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

    fn test_namespace_verification_impl<const NS_ID_SIZE: usize>() {
        let mut tree = DefaultNmt::<NS_ID_SIZE>::new();
        // Put a bunch of data in the tree
        for x in 0..33 {
            // Ensure that some namespaces are skipped, including the zero namespace
            let namespace = ns_id_from_u64(((x / 5) * 3) + 1);
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
                .verify_namespace(&root, &raw_leaves[range.clone()], *namespace, &proof)
                .is_ok());
        }

        // Build and check proofs for a bunch of namespaces, including some that are present and some that are absent.
        for nid in 0..100u64 {
            let namespace = ns_id_from_u64(nid);
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

    #[test]
    fn test_namespace_verification() {
        test_namespace_verification_impl::<8>();
        test_namespace_verification_impl::<17>();
        test_namespace_verification_impl::<24>();
        test_namespace_verification_impl::<CELESTIA_NS_ID_SIZE>();
        test_namespace_verification_impl::<32>();
    }
}
