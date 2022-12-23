#![feature(slice_take)]
use std::{collections::HashMap, ops::Range};

use db::{LeafWithHash, MemDb, Node, PreimageDb};

mod namespaced_hash;
pub use namespaced_hash::*;

pub mod db;

#[derive(Debug, PartialEq, Clone)]
/// A proof of some statement about a namespaced merkle tree.
///
/// This proof may prove the presence of some set of leaves, or the
/// absence of a particular namespace
pub enum Proof {
    AbsenceProof {
        siblings: Vec<NamespacedHash>,
        start_idx: u32,
        ignore_max_ns: bool,
        leaf: Option<NamespacedHash>,
    },
    PresenceProof {
        siblings: Vec<NamespacedHash>,
        start_idx: u32,
        ignore_max_ns: bool,
    },
}

impl Proof {
    /// Verify that the provided *raw* leaves occur in the provided namespace, using this proof
    pub fn verify_complete_namespace(
        self,
        root: &NamespacedHash,
        raw_leaves: &[impl AsRef<[u8]>],
        namespace: NamespaceId,
    ) -> Result<(), RangeProofError> {
        let mut tree = NamespaceMerkleTree::<MemDb>::new();
        tree.ignore_max_ns = self.ignores_max_ns();
        tree.verify_namespace(root, raw_leaves, namespace, self)
    }

    /// Verify a range proof
    pub fn verify_range(
        self,
        root: &NamespacedHash,
        raw_leaves: &[impl AsRef<[u8]>],
        leaf_namespace: NamespaceId,
    ) -> Result<(), RangeProofError> {
        let mut tree = NamespaceMerkleTree::<MemDb>::new();
        if let Proof::PresenceProof {
            mut siblings,
            ignore_max_ns,
            start_idx,
        } = self
        {
            tree.ignore_max_ns = ignore_max_ns;

            let leaf_hashes: Vec<NamespacedHash> = raw_leaves
                .iter()
                .map(|data| NamespacedHash::hash_leaf(data.as_ref(), leaf_namespace))
                .collect();
            tree.check_range_proof(
                root,
                &mut &leaf_hashes[..],
                &mut siblings,
                start_idx as usize,
            )?;
            Ok(())
        } else {
            Err(RangeProofError::MalformedProof)
        }
    }
    fn convert_to_absence_proof(&mut self, leaf: NamespacedHash) {
        match self {
            Proof::AbsenceProof { .. } => {}
            Proof::PresenceProof {
                siblings,
                start_idx,
                ignore_max_ns,
            } => {
                let siblings = std::mem::take(siblings);
                *self = Self::AbsenceProof {
                    siblings,
                    start_idx: *start_idx,
                    ignore_max_ns: *ignore_max_ns,
                    leaf: Some(leaf),
                }
            }
        }
    }

    pub fn siblings(&self) -> &Vec<NamespacedHash> {
        match self {
            Proof::AbsenceProof { siblings, .. } => siblings,
            Proof::PresenceProof { siblings, .. } => siblings,
        }
    }

    pub fn start_idx(&self) -> u32 {
        match self {
            Proof::AbsenceProof {
                siblings: _,
                start_idx,
                ..
            } => *start_idx,
            Proof::PresenceProof {
                siblings: _,
                start_idx,
                ..
            } => *start_idx,
        }
    }
    pub fn leftmost_right_sibling(&self) -> Option<&NamespacedHash> {
        let siblings = self.siblings();
        let num_left_siblings = compute_num_left_siblings(self.start_idx() as usize);
        if siblings.len() > num_left_siblings {
            return Some(&siblings[num_left_siblings]);
        }
        None
    }

    pub fn rightmost_left_sibling(&self) -> Option<&NamespacedHash> {
        let siblings = self.siblings();
        let num_left_siblings = compute_num_left_siblings(self.start_idx() as usize);
        if num_left_siblings != 0 && num_left_siblings <= siblings.len() {
            return Some(&siblings[num_left_siblings - 1]);
        }
        None
    }

    #[cfg(test)]
    fn take_siblings(self) -> Vec<NamespacedHash> {
        match self {
            Proof::AbsenceProof { siblings, .. } => siblings,
            Proof::PresenceProof { siblings, .. } => siblings,
        }
    }

    fn ignores_max_ns(&self) -> bool {
        match self {
            Proof::AbsenceProof {
                siblings: _,
                start_idx: _,
                ignore_max_ns,
                ..
            } => *ignore_max_ns,
            Proof::PresenceProof {
                siblings: _,
                start_idx: _,
                ignore_max_ns,
                ..
            } => *ignore_max_ns,
        }
    }

    pub fn is_of_absence(&self) -> bool {
        match self {
            Self::AbsenceProof { .. } => true,
            Self::PresenceProof { .. } => false,
        }
    }
}

/// Compute the number of left siblings required for an inclusion proof of the node at the provided index
fn compute_num_left_siblings(node_idx: usize) -> usize {
    // The number of left siblings needed is the same as the number of ones in the binary
    // decomposition of the start index
    let mut num_left_siblings = 0;
    let mut start_idx = node_idx;
    while start_idx != 0 {
        if start_idx & 1 != 0 {
            num_left_siblings += 1;
        }
        start_idx >>= 1;
    }
    num_left_siblings
}

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

// Reconstruct the size of the tree.
// This trick works by interpreting the binary representation of the index of a node as a *path*
// to the node. If the lsb of the (remaining) path is a 1, turn right. Otherwise, turn left.
fn compute_tree_size(
    num_right_siblings: usize,
    index_of_last_included_leaf: usize,
) -> Result<usize, RangeProofError> {
    // Each right sibling converts a left turn into a right turn - replacing a
    // zero in the path with a one.
    let mut index_of_final_node = index_of_last_included_leaf;
    let mut mask = 1;
    let mut remaining_right_siblings = num_right_siblings;
    while remaining_right_siblings > 0 {
        if index_of_final_node & mask == 0 {
            index_of_final_node |= mask;
            remaining_right_siblings -= 1;
        }
        mask <<= 1;
        // Ensure that the next iteration won't overflow on 32 bit platforms
        if index_of_final_node == u32::MAX as usize {
            return Err(RangeProofError::TreeTooLarge);
        }
    }
    Ok(index_of_final_node + 1)
}

pub struct NamespaceMerkleTree<Db> {
    leaves: Vec<LeafWithHash>,
    db: Db,
    ignore_max_ns: bool,
    namespace_ranges: HashMap<NamespaceId, Range<usize>>,
    root: Option<NamespacedHash>,
    visitor: Box<dyn Fn(&NamespacedHash)>,
}

impl<Db> NamespaceMerkleTree<Db>
where
    Db: PreimageDb,
{
    pub fn new() -> Self {
        Self {
            leaves: vec![],
            ignore_max_ns: true,
            namespace_ranges: Default::default(),
            db: Default::default(),
            root: Some(EMPTY_ROOT.clone()),
            visitor: Box::new(|_| {}),
        }
    }

    pub fn push_leaf(&mut self, raw_data: &[u8], namespace: NamespaceId) -> Result<(), ()> {
        self.root = None;
        if let Some(last_leaf) = self.leaves.last() {
            if last_leaf.hash.max_namespace() > namespace {
                return Err(());
            }
        }

        let hash = NamespacedHash::hash_leaf(raw_data, namespace);
        let leaf = LeafWithHash {
            hash,
            data: raw_data.to_vec(),
        };
        self.leaves.push(leaf);
        match self.namespace_ranges.entry(namespace) {
            std::collections::hash_map::Entry::Occupied(entry) => {
                entry.into_mut().end = self.leaves.len();
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(self.leaves.len() - 1..self.leaves.len());
            }
        }
        Ok(())
    }

    pub fn root(&mut self) -> NamespacedHash {
        if let Some(inner) = &self.root {
            return inner.clone();
        }
        let inner = self.compute_root(0..self.leaves.len());
        self.root = Some(inner.clone());
        inner
    }

    fn compute_root(&mut self, leaf_range: Range<usize>) -> NamespacedHash {
        match leaf_range.len() {
            0 => {
                let root = NamespacedHash::empty();
                (self.visitor)(&root);
                root
            }
            1 => {
                let leaf_with_hash = &self.leaves[leaf_range.start];
                let root = leaf_with_hash.hash.clone();
                (self.visitor)(&root);
                self.db
                    .put(root.clone(), Node::Leaf(leaf_with_hash.data.clone()));
                root
            }
            _ => {
                let split_point = next_smaller_po2(leaf_range.len()) + leaf_range.start;
                let left = self.compute_root(leaf_range.start..split_point);
                let right = self.compute_root(split_point..leaf_range.end);
                let root =
                    NamespacedHash::hash_nodes(left.clone(), right.clone(), self.ignore_max_ns);
                (self.visitor)(&root);
                self.db.put(root.clone(), Node::Inner(left, right));
                root
            }
        }
    }

    fn build_range_proof_inner(
        &self,
        range_to_prove: Range<usize>,
        subtrie_root: NamespacedHash,
        subtrie_range: Range<usize>,
        mut out: &mut Vec<NamespacedHash>,
    ) {
        if let Some(inner_node) = self.db.get(&subtrie_root) {
            match inner_node {
                // If we've bottomed out, return the leaf hash
                Node::Leaf(_) => {
                    if !range_to_prove.contains(&subtrie_range.start) {
                        out.push(subtrie_root.clone())
                    }
                }
                Node::Inner(l, r) => {
                    let split_point = next_smaller_po2(subtrie_range.len()) + subtrie_range.start;
                    // If the range to prove, doesn't overlap with the left subtrie, add the left subtrie root to the proof.
                    // We're now done with the left subtrie
                    if range_to_prove.start >= split_point {
                        out.push(l.clone())
                    //  If the range of nodes to prove completely contains the left subtrie, then we don't need to recurse.
                    } else if range_to_prove.start > subtrie_range.start
                        || range_to_prove.end < split_point
                    {
                        self.build_range_proof_inner(
                            range_to_prove.clone(),
                            l.clone(),
                            subtrie_range.start..split_point,
                            &mut out,
                        );
                    }

                    // Similarly, if the range to prove, doesn't overlap with the right subtrie, add the right subtrie root to the proof and return
                    if range_to_prove.end <= split_point {
                        out.push(r.clone())
                    } else if range_to_prove.start > split_point
                        || range_to_prove.end < subtrie_range.end
                    {
                        self.build_range_proof_inner(
                            range_to_prove,
                            r.clone(),
                            split_point..subtrie_range.end,
                            &mut out,
                        );
                    }
                }
            }
        } else {
            assert!(subtrie_root.is_empty_root());
            return out.push(subtrie_root);
        }
    }

    fn check_range_proof_inner(
        &self,
        leaves: &mut &[NamespacedHash],
        mut proof: &mut Vec<NamespacedHash>,
        leaves_start_idx: usize,
        subtrie_size: usize,
        offset: usize,
    ) -> Result<NamespacedHash, RangeProofError> {
        let split_point = next_smaller_po2(subtrie_size);

        let leaves_end_idx = (leaves.len() + leaves_start_idx) - 1;

        // If the leaf range overlaps with the right subtree
        let right = if leaves_end_idx >= (split_point + offset) {
            let right_subtrie_size = subtrie_size - split_point;
            // If the right subtree contains only a single node, it must be the last remaining leaf
            if right_subtrie_size == 1 {
                leaves
                    .take_last()
                    .ok_or(RangeProofError::MissingLeaf)?
                    .clone()
            } else {
                // Recurse right
                self.check_range_proof_inner(
                    leaves,
                    &mut proof,
                    leaves_start_idx,
                    right_subtrie_size,
                    offset + split_point,
                )?
            }
        } else {
            // Otherwise (if the leaf range doesn't overlap with the right subtree),
            // the sibling node must have been included in the range proof
            proof.pop().ok_or(RangeProofError::MissingProofNode)?
        };

        // Similarly, // If the leaf range overlaps with the left subtree
        let left = if leaves_start_idx < (split_point + offset) {
            let left_subtrie_size = split_point;
            // If the right subtree contains only a single node, it must be the last remaining leaf
            if left_subtrie_size == 1 {
                leaves
                    .take_last()
                    .ok_or(RangeProofError::MissingLeaf)?
                    .clone()
            } else {
                // Recurse left
                self.check_range_proof_inner(
                    leaves,
                    &mut proof,
                    leaves_start_idx,
                    left_subtrie_size,
                    offset,
                )?
            }
        } else {
            // Otherwise (if the leaf range doesn't overlap with the right subtree),
            // the sibling node must have been included in the range proof
            proof.pop().ok_or(RangeProofError::MissingProofNode)?
        };

        if left.max_namespace() > right.min_namespace() {
            return Err(RangeProofError::MalformedTree);
        }

        Ok(NamespacedHash::hash_nodes(left, right, self.ignore_max_ns))
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
                if root == &NamespacedHash::empty() && proof.len() == 0 {
                    return Ok(RangeProofType::Complete);
                }
                return Err(RangeProofError::NoLeavesProvided);
            }
            1 => {
                if proof.len() == 0 {
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
        let num_right_siblings = proof
            .len()
            .checked_sub(num_left_siblings)
            .ok_or(RangeProofError::MissingProofNode)?;

        let tree_size = compute_tree_size(num_right_siblings, leaves_start_idx + leaves.len() - 1)?;
        let proof_completeness = check_proof_completeness(leaves, proof, num_left_siblings);

        let computed_root =
            self.check_range_proof_inner(&mut &leaves[..], proof, leaves_start_idx, tree_size, 0)?;
        if &computed_root == root {
            return Ok(proof_completeness);
        }
        Err(RangeProofError::InvalidRoot)
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
    pub fn build_range_proof(&mut self, leaf_range: Range<usize>) -> Proof {
        // Calculate the root to ensure that the preimage db is populated
        let root = self.root();
        let mut proof = Vec::new();
        let start_idx = leaf_range.start as u32;
        if leaf_range.end > self.leaves.len() {
            panic!(
                "Index out of range: cannot access leaf {} in leaves array of size {}",
                leaf_range.end,
                self.leaves.len()
            )
        }
        self.build_range_proof_inner(leaf_range, root, 0..self.leaves.len(), &mut proof);

        Proof::PresenceProof {
            siblings: proof,
            start_idx,
            ignore_max_ns: self.ignore_max_ns,
        }
    }

    pub fn get_range_with_proof(&mut self, leaf_range: Range<usize>) -> (Vec<Vec<u8>>, Proof) {
        let leaves = &self.leaves[leaf_range.clone()];
        let leaves = leaves.iter().map(|leaf| leaf.data.clone()).collect();
        (leaves, self.build_range_proof(leaf_range))
    }

    pub fn get_index_with_proof(&mut self, idx: usize) -> (Vec<u8>, Proof) {
        (
            self.leaves[idx].data.clone(),
            self.build_range_proof(idx..idx + 1),
        )
    }

    pub fn get_namespace_with_proof(&mut self, namespace: NamespaceId) -> (Vec<Vec<u8>>, Proof) {
        let leaf_range = if let Some(range) = self.namespace_ranges.get(&namespace) {
            range.clone()
        } else {
            0..0
        };
        let leaves = &self.leaves[leaf_range];
        let leaves = leaves.iter().map(|leaf| leaf.data.clone()).collect();
        (leaves, self.get_namespace_proof(namespace))
    }

    pub fn get_namespace_proof(&mut self, namespace: NamespaceId) -> Proof {
        // If the namespace is outside the range covered by the root, we're done
        if !self.root().contains(namespace) {
            return Proof::AbsenceProof {
                siblings: vec![],
                start_idx: 0,
                ignore_max_ns: self.ignore_max_ns,
                leaf: None,
            };
        }

        // If the namespace has data, just look up that namespace range and prove it by index
        if let Some(leaf_range) = self.namespace_ranges.get(&namespace) {
            return self.build_range_proof(leaf_range.clone());
        }

        // Otherwise, the namespace is within the range covered by the tree, but doesn't actually exist.
        // To prove this, we can prove that for some index `i`, leaves[i].namespace() < namespace < leaves[i+1].namespace().
        // Since a range proof for the range [i, i+1) includes the namespaced hash of leaf i+1,
        // proving this range is sufficient to establish that the namespace doesn't exist.
        let namespace = self
            .leaves
            .binary_search_by(|l| l.hash.min_namespace().cmp(&namespace));

        // The builtin binary search method returns the index where the item could be inserted while maintaining sorted order,
        // which is the index after the leaf we want to prove
        let idx =
            namespace.expect_err("tree cannot contain leaf with namespace that does not exist") - 1;

        let mut proof = self.build_range_proof(idx..idx + 1);
        proof.convert_to_absence_proof(self.leaves[idx].hash.clone());
        proof
    }

    fn verify_namespace(
        &self,
        root: &NamespacedHash,
        raw_leaves: &[impl AsRef<[u8]>],
        namespace: NamespaceId,
        proof: Proof,
    ) -> Result<(), RangeProofError> {
        if root.is_empty_root() && raw_leaves.len() == 0 {
            return Ok(());
        }

        match proof {
            Proof::AbsenceProof {
                mut siblings,
                leaf,
                ignore_max_ns: _,
                start_idx,
            } => {
                if !root.contains(namespace) {
                    return Ok(());
                }
                let leaf = leaf.ok_or(RangeProofError::MalformedProof)?;
                // Check that they haven't provided an absence proof for a non-empty namespace
                if raw_leaves.len() != 0 {
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
                self.check_range_proof(root, &[leaf], &mut siblings, start_idx as usize)?;
            }
            Proof::PresenceProof {
                mut siblings,
                ignore_max_ns: _,
                start_idx,
            } => {
                if !root.contains(namespace) {
                    return Err(RangeProofError::TreeDoesNotContainLeaf);
                }
                let leaf_hashes: Vec<NamespacedHash> = raw_leaves
                    .iter()
                    .map(|data| NamespacedHash::hash_leaf(data.as_ref(), namespace))
                    .collect();
                self.check_range_proof(
                    root,
                    &mut &leaf_hashes[..],
                    &mut siblings,
                    start_idx as usize,
                )?;
            }
        }
        Ok(())
    }
}

/// Calculates the largest power of two which is strictly less than the argument
fn next_smaller_po2(int: usize) -> usize {
    // Calculate the first power of two which is greater than or equal to the argument, then divide by two.
    int.next_power_of_two() >> 1
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum RangeProofError {
    NoLeavesProvided,
    InvalidRoot,
    MissingLeaf,
    MissingProofNode,
    TreeDoesNotContainLeaf,
    TreeIsEmpty,
    TreeTooLarge,
    /// Indicates that the tree is not properly ordered by namespace
    MalformedTree,
    MalformedProof,
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

impl std::fmt::Display for RangeProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RangeProofError::NoLeavesProvided => f.write_str("RangeProofError::NoLeavesProvided"),
            RangeProofError::InvalidRoot => f.write_str("RangeProofError::InvalidRoot"),
            RangeProofError::MissingLeaf => f.write_str("RangeProofError::MissingLeaf"),
            RangeProofError::MissingProofNode => f.write_str("RangeProofError::MissingProofNode"),
            RangeProofError::TreeDoesNotContainLeaf => {
                f.write_str("RangeProofError::TreeDoesNotContainLeaf")
            }
            RangeProofError::TreeIsEmpty => f.write_str("RangeProofError::TreeIsEmpty"),
            RangeProofError::TreeTooLarge => f.write_str("RangeProofError::TreeTooLarge"),
            RangeProofError::MalformedTree => f.write_str("RangeProofError::MalformedTree"),
            RangeProofError::MalformedProof => f.write_str("RangeProofError::MalformedProof"),
        }
    }
}

impl std::error::Error for RangeProofError {}

#[cfg(test)]
mod tests {
    use crate::{
        namespaced_hash::NamespaceId, MemDb, NamespaceMerkleTree, NamespacedHash, RangeProofType,
        NAMESPACE_ID_LEN,
    };

    /// Builds a tree with N leaves
    fn tree_with_n_leaves(n: usize) -> NamespaceMerkleTree<MemDb> {
        let mut tree = NamespaceMerkleTree::<MemDb>::new();
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
                    tree.leaves[j..i].iter().map(|l| l.hash.clone()).collect();
                let res = tree.check_range_proof(
                    &root,
                    &mut &leaf_hashes[..],
                    &mut proof.take_siblings(),
                    j,
                );
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
    fn test_min_and_max_ns_against(tree: &mut NamespaceMerkleTree<MemDb>) {
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
        let mut tree = NamespaceMerkleTree::<MemDb>::new();
        for x in 0..32 {
            let namespace = crate::NamespaceId((x / 4 as u64).to_be_bytes());
            let _ = tree.push_leaf(x.to_be_bytes().as_ref(), namespace);
        }
        let root = tree.root();
        let leaf_hashes: Vec<NamespacedHash> = tree.leaves.iter().map(|x| x.hash.clone()).collect();

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
            if !pf.is_ok() {
                dbg!(&pf, namespace);
                println!("{:?}", &leaves);
            }
            assert!(pf.is_ok());
        }
    }
    #[test]
    fn test_namespace_verification() {
        let mut tree = NamespaceMerkleTree::<MemDb>::new();
        // Put a bunch of data in the tree
        for x in 0..33 {
            // Ensure that some namespaces are skipped, including the zero namespace
            let namespace = crate::NamespaceId((((x / 5 as u64) * 3) + 1).to_be_bytes());
            let _ = tree.push_leaf(x.to_be_bytes().as_ref(), namespace);
        }
        let root = tree.root();
        let leaves = tree.leaves.clone();
        let raw_leaves: Vec<&[u8]> = leaves.iter().map(|x| x.data.as_ref()).collect();

        // Build proofs for each range that's actually included, and check that the range can be retrieved correctly
        for (namespace, range) in tree.namespace_ranges.clone().iter() {
            let proof = tree.build_range_proof(range.clone());
            assert!(!range.is_empty());

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
            if !pf.is_ok() {
                dbg!(&pf, namespace);
                println!("{:?}", &leaves);
            }
            assert!(pf.is_ok());
        }

        test_min_and_max_ns_against(&mut tree)
    }
}
