#![feature(slice_take)]
use std::{collections::HashMap, hash::Hash, ops::Range};

use sha2::{Digest, Sha256};

const HASH_LEN: usize = 32;
const NAMESPACE_ID_LEN: usize = 8;
const NAMESPACED_HASH_LEN: usize = HASH_LEN + 2 * NAMESPACE_ID_LEN;
pub type Hasher = Sha256;

pub const LEAF_DOMAIN_SEPARATOR: [u8; 1] = [0u8];
pub const INTERNAL_NODE_DOMAIN_SEPARATOR: [u8; 1] = [1u8];

pub const EMPTY_ROOT: NamespacedHash = NamespacedHash([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 227, 176, 196, 66, 152, 252, 28, 20, 154, 251,
    244, 200, 153, 111, 185, 36, 39, 174, 65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82,
    184, 85,
]);

#[derive(Debug, PartialEq, PartialOrd, Eq, Ord, Copy, Clone, Hash)]
pub struct NamespaceId(pub [u8; NAMESPACE_ID_LEN]);

impl AsRef<[u8]> for NamespaceId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

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
    pub fn verify(
        self,
        root: &NamespacedHash,
        raw_leaves: &[&[u8]],
        namespace: NamespaceId,
    ) -> Result<(), RangeProofError> {
        let mut tree = NamespaceMerkleTree::<MemDb>::new();
        tree.ignore_max_ns = self.ignores_max_ns();
        tree.verify_namespace(root, raw_leaves, namespace, self)
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
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub struct InvalidNamespace;

impl std::fmt::Display for InvalidNamespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InvalidNamespace")
    }
}
impl std::error::Error for InvalidNamespace {}

impl TryFrom<&[u8]> for NamespaceId {
    type Error = InvalidNamespace;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != NAMESPACE_ID_LEN {
            return Err(InvalidNamespace);
        }
        let mut out = [0u8; NAMESPACE_ID_LEN];
        out.copy_from_slice(value);
        Ok(Self(out))
    }
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct NamespacedHash(pub [u8; NAMESPACED_HASH_LEN]);

impl NamespacedHash {
    pub fn with_min_and_max_ns(min_namespace: NamespaceId, max_namespace: NamespaceId) -> Self {
        let mut out = Self([0u8; NAMESPACED_HASH_LEN]);
        out.0[0..NAMESPACE_ID_LEN].copy_from_slice(min_namespace.as_ref());
        out.0[NAMESPACE_ID_LEN..2 * NAMESPACE_ID_LEN].copy_from_slice(max_namespace.as_ref());
        out
    }
    pub fn min_namespace(&self) -> NamespaceId {
        let mut out = [0u8; NAMESPACE_ID_LEN];
        out.copy_from_slice(&self.0[..NAMESPACE_ID_LEN]);
        NamespaceId(out)
    }

    pub fn max_namespace(&self) -> NamespaceId {
        let mut out = [0u8; NAMESPACE_ID_LEN];
        out.copy_from_slice(&self.0[NAMESPACE_ID_LEN..2 * NAMESPACE_ID_LEN]);
        NamespaceId(out)
    }

    fn set_hash(&mut self, hash: &[u8]) {
        self.0[2 * NAMESPACE_ID_LEN..].copy_from_slice(hash)
    }

    pub fn hash_leaf<'a>(raw_data: &'a [u8], namespace: NamespaceId) -> Self {
        let mut output = NamespacedHash::with_min_and_max_ns(namespace, namespace);
        let mut hasher = Hasher::new_with_prefix(&LEAF_DOMAIN_SEPARATOR);
        hasher.update(namespace.as_ref());
        hasher.update(raw_data);
        output.set_hash(hasher.finalize().as_ref());
        output
    }

    pub fn empty() -> Self {
        EMPTY_ROOT.clone()
    }

    pub fn contains(&self, namespace: NamespaceId) -> bool {
        (self.min_namespace() <= namespace && self.max_namespace() >= namespace)
            || self.is_empty_root()
    }

    pub fn is_empty_root(&self) -> bool {
        self == &EMPTY_ROOT
    }
}

impl AsRef<[u8]> for NamespacedHash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[derive(Default)]
pub struct MemDb(HashMap<NamespacedHash, Node>);

impl PreimageReader for MemDb {
    fn get(&self, image: &NamespacedHash) -> Option<&Node> {
        self.0.get(image)
    }
}
impl PreimageWriter for MemDb {
    fn put(&mut self, image: NamespacedHash, preimage: Node) {
        self.0.insert(image, preimage);
    }
}

impl PreimageDb for MemDb {}

#[derive(Clone)]
struct LeafWithHash {
    data: Vec<u8>,
    pub hash: NamespacedHash,
}

#[derive(PartialEq, Clone, Debug)]
pub enum Node {
    Leaf(Vec<u8>),
    Inner(NamespacedHash, NamespacedHash),
}

pub trait PreimageReader {
    fn get(&self, image: &NamespacedHash) -> Option<&Node>;
}

pub trait PreimageWriter {
    fn put(&mut self, image: NamespacedHash, preimage: Node);
}

pub trait PreimageDb: PreimageReader + PreimageWriter + Default {}

pub struct NamespaceMerkleTree<Db> {
    leaves: Vec<LeafWithHash>,
    db: Db,
    ignore_max_ns: bool,
    precomputed_max_ns: NamespaceId,
    min_namespace: NamespaceId,
    max_namespace: NamespaceId,
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
            precomputed_max_ns: NamespaceId([0xff; NAMESPACE_ID_LEN]),
            // Initialize the min namespace to be the maximum possible, so that the check
            // x <= tree.min_namespace is always true for the empty tree
            min_namespace: NamespaceId([0xff; NAMESPACE_ID_LEN]),
            // Similarly set the max namespace to be the maximum possible, so that the check
            // x >= tree.max_namespace is always true for the empty tree
            max_namespace: NamespaceId([0x00; NAMESPACE_ID_LEN]),
            namespace_ranges: Default::default(),
            db: Default::default(),
            root: Some(EMPTY_ROOT.clone()),
            visitor: Box::new(|_| {}),
        }
    }

    pub fn push_leaf(&mut self, raw_data: &[u8], namespace: NamespaceId) {
        self.root = None;
        assert!(namespace >= self.max_namespace);
        self.update_min_max_ids(namespace);

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
    }

    fn update_min_max_ids(&mut self, namespace: NamespaceId) {
        // Note: these two conditions are not mutually exclusive!
        // We initialize min_namespace to be greater than max_namespace
        if namespace < self.min_namespace {
            self.min_namespace = namespace
        }
        if namespace > self.max_namespace {
            self.max_namespace = namespace
        }
    }

    pub fn hash_nodes(&self, left: NamespacedHash, right: NamespacedHash) -> NamespacedHash {
        let mut hasher = Hasher::new_with_prefix(INTERNAL_NODE_DOMAIN_SEPARATOR);

        let min_ns = std::cmp::min(left.min_namespace(), right.min_namespace());
        let max_ns = if self.ignore_max_ns && left.min_namespace() == self.precomputed_max_ns {
            self.precomputed_max_ns
        } else if self.ignore_max_ns && right.min_namespace() == self.precomputed_max_ns {
            left.max_namespace()
        } else {
            std::cmp::max(left.max_namespace(), right.max_namespace())
        };

        let mut output = NamespacedHash::with_min_and_max_ns(min_ns, max_ns);

        hasher.update(left);
        hasher.update(right);

        output.set_hash(hasher.finalize().as_ref());
        output
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
                let root = self.hash_nodes(left.clone(), right.clone());
                (self.visitor)(&root);
                self.db.put(root.clone(), Node::Inner(left, right));
                root
            }
        }
    }

    fn build_range_proof_inner(
        &self,
        range_to_prove: Range<usize>,
        // remaining_leaves: Range<usize>,
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

        Ok(self.hash_nodes(left, right))
    }

    /// Checks a given range proof
    fn check_range_proof(
        &self,
        root: &NamespacedHash,
        leaves: &[NamespacedHash],
        proof: &mut Vec<NamespacedHash>,
        leaves_start_idx: usize,
    ) -> Result<RangeProofType, RangeProofError> {
        if root == &NamespacedHash::empty() {
            if leaves.len() == 0 && proof.len() == 0 {
                return Ok(RangeProofType::Complete);
            } else {
                return Err(RangeProofError::TreeIsEmpty);
            }
        }

        if leaves.len() == 0 {
            return Err(RangeProofError::NoLeavesProvided);
        }

        if leaves.len() == 1 && proof.len() == 0 {
            if &leaves[0] == root && leaves_start_idx == 0 {
                return Ok(RangeProofType::Complete);
            }
            return Err(RangeProofError::TreeDoesNotContainLeaf);
        }

        for hash in proof.iter() {
            if hash.min_namespace() > hash.max_namespace() {
                return Err(RangeProofError::MalformedTree);
            }
        }

        // Do binary decomposition magic to reconstruct the size of the binary tree
        // from the proof. This trick works by interpreting the index of a node as a *path*
        // to the node. If the leading bit is a path, turn right. Otherwise, go left.
        let mut proof_type = RangeProofType::Complete;
        let tree_size = {
            // The number of left siblings needed is the same as the number of ones in the binary
            // decomposition of the start index
            let mut num_left_siblings = 0;
            let mut start_idx = leaves_start_idx;
            while start_idx != 0 {
                if start_idx & 1 != 0 {
                    num_left_siblings += 1;
                }
                start_idx >>= 1;
            }

            // Prevent underflow
            if proof.len() < num_left_siblings {
                return Err(RangeProofError::MissingProofNode);
            }
            // Check if the proof is complete
            if num_left_siblings != 0 {
                let rightmost_left_sibling = &proof[num_left_siblings - 1];
                if rightmost_left_sibling.max_namespace() >= leaves[0].min_namespace() {
                    proof_type = RangeProofType::Partial
                }
            }

            // Each right sibling converts a left turn into a right turn - replacing a
            // zero in the path with a one.
            let mut index_of_final_node = leaves_start_idx + leaves.len() - 1;
            let right_siblings = proof.len() - num_left_siblings;
            if right_siblings != 0 {
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

            let mut mask = 1;
            let mut remaining_right_siblings = right_siblings;
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

            // the size of the tree is the index of the last node plus one (since we use zero-based indexing)
            index_of_final_node + 1
        };

        let computed_root =
            self.check_range_proof_inner(&mut &leaves[..], proof, leaves_start_idx, tree_size, 0)?;
        if &computed_root == root {
            return Ok(proof_type);
        }
        Err(RangeProofError::InvalidRoot)
    }

    /// Creates a range proof providing the sibling hashes required to show that a set of values really does occur in
    /// the merkle tree at some half-open range of indices. Intermediate hashes are identified by an in-order traversal
    /// and are returned in that same order.
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
    fn build_range_proof(&mut self, leaf_range: Range<usize>) -> Proof {
        // Calculate the root to ensure that the preimage db is populated
        let root = self.root();
        let mut proof = Vec::new();
        let start_idx = leaf_range.start as u32;
        self.build_range_proof_inner(leaf_range, root, 0..self.leaves.len(), &mut proof);

        Proof::PresenceProof {
            siblings: proof,
            start_idx,
            ignore_max_ns: self.ignore_max_ns,
        }
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
        // To prove this, we can actually just prove that for some index `i`,
        // leaves[i].namespace() < namespace < leaves[i+1].namespace(). Since a range proof for the range [i, i+1)
        // Includes the namespaced hash of leaf i+1, proving this range is sufficient.
        let namespace = self
            .leaves
            .binary_search_by(|l| l.hash.min_namespace().cmp(&namespace));

        // The builtin binary search method returns the index where the item could be inserted while maintaining sorted order,
        // which is the index after the leaf we want to prove
        let following_idx =
            namespace.expect_err("tree cannot contain leaf with namespace that does not exist");

        let idx = following_idx - 1;

        let mut proof = self.build_range_proof(idx..idx + 1);
        proof.convert_to_absence_proof(self.leaves[idx].hash.clone());
        proof
    }

    /// Verifies that some set of leaves is a complete and correct representation of the data from a particular
    /// range of namespaces.
    fn verify_leaf_hashes(
        &self,
        root: &NamespacedHash,
        leaf_hashes: &[NamespacedHash],
        mut proof: Vec<NamespacedHash>,
        leaves_start_idx: usize,
    ) -> Result<(), RangeProofError> {
        let proof_type =
            self.check_range_proof(&root, leaf_hashes, &mut proof, leaves_start_idx)?;
        match proof_type {
            RangeProofType::Complete => Ok(()),
            RangeProofType::Partial => Err(RangeProofError::MissingLeaf),
        }
    }

    // /// Verifies that some set of leaves is a complete and correct representation of the data from a particular
    // /// range of namespaces.
    // pub fn verify_namespaced_leaf_hashes(
    //     &self,
    //     root: &NamespacedHash,
    //     leaf_hashes: &[NamespacedHash],
    //     mut proof: Vec<NamespacedHash>,
    //     leaves_start_idx: usize,
    // ) -> Result<(), RangeProofError> {
    //     let proof_type =
    //         self.check_range_proof(&root, leaf_hashes, &mut proof, leaves_start_idx)?;
    //     match proof_type {
    //         RangeProofType::Complete => Ok(()),
    //         RangeProofType::Partial => Err(RangeProofError::MissingLeaf),
    //     }
    // }

    fn verify_namespace(
        &self,
        root: &NamespacedHash,
        raw_leaves: &[&[u8]],
        namespace: NamespaceId,
        proof: Proof,
    ) -> Result<(), RangeProofError> {
        if root.is_empty_root() && raw_leaves.len() == 0 {
            return Ok(());
        }

        match proof {
            Proof::AbsenceProof {
                siblings,
                leaf,
                ignore_max_ns: _,
                start_idx,
            } => {
                let leaf = leaf.ok_or(RangeProofError::MalformedProof)?;
                // Check that they haven't provided an absence proof for a non-empty namespace
                if raw_leaves.len() != 0 {
                    return Err(RangeProofError::MalformedProof);
                }
                // Check that the provided leaf actually precedes the namespace
                if leaf.max_namespace() >= namespace {
                    return Err(RangeProofError::MalformedProof);
                }
                // The number of left siblings needed is the same as the number of ones in the binary
                // decomposition of the start index
                let mut num_left_siblings = 0;
                let mut modified_start_idx = start_idx;
                while modified_start_idx != 0 {
                    if modified_start_idx & 1 != 0 {
                        num_left_siblings += 1;
                    }
                    modified_start_idx >>= 1;
                }

                // Check that the closest sibling actually follows the namespace
                if siblings.len() >= num_left_siblings {
                    let leftmost_right_sibling = &siblings[num_left_siblings - 1];
                    if leftmost_right_sibling.min_namespace() <= namespace {
                        return Err(RangeProofError::MalformedProof);
                    }
                }
                // Then, check that the root is real
                self.verify_leaf_hashes(root, &[leaf], siblings, start_idx as usize)
            }
            Proof::PresenceProof {
                siblings,
                ignore_max_ns: _,
                start_idx,
            } => {
                let leaf_hashes: Vec<NamespacedHash> = raw_leaves
                    .iter()
                    .map(|data| NamespacedHash::hash_leaf(data, namespace))
                    .collect();
                self.verify_leaf_hashes(root, &mut &leaf_hashes[..], siblings, start_idx as usize)
            }
        }
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
    use crate::{MemDb, NamespaceMerkleTree, NamespacedHash, RangeProofType};

    /// Builds a tree with N leaves
    fn tree_with_n_leaves(n: usize) -> NamespaceMerkleTree<MemDb> {
        let mut tree = NamespaceMerkleTree::<MemDb>::new();
        for x in 0..n {
            let namespace = crate::NamespaceId((x as u64).to_be_bytes());
            tree.push_leaf(x.to_be_bytes().as_ref(), namespace)
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
                    assert!(res.is_ok());
                    assert!(res.unwrap() == RangeProofType::Complete)
                } else {
                    // Cannot prove the empty range!
                    assert!(res.is_err())
                }
            }
        }
    }
    #[test]
    fn test_range_proof_roundtrip() {
        for x in 0..20 {
            test_range_proof_roundtrip_with_n_leaves(x)
        }
    }

    #[test]
    fn test_completeness_check() {
        // Build a tree with 32 leaves spread evenly across 8 namespaces
        let mut tree = NamespaceMerkleTree::<MemDb>::new();
        for x in 0..32 {
            let namespace = crate::NamespaceId((x / 4 as u64).to_be_bytes());
            tree.push_leaf(x.to_be_bytes().as_ref(), namespace)
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
    }
    #[test]
    fn test_namespace_verification() {
        let mut tree = NamespaceMerkleTree::<MemDb>::new();
        for x in 0..33 {
            let namespace = crate::NamespaceId((x / 5 as u64).to_be_bytes());
            tree.push_leaf(x.to_be_bytes().as_ref(), namespace)
        }
        let root = tree.root();
        let leaves = tree.leaves.clone();
        let raw_leaves: Vec<&[u8]> = leaves.iter().map(|x| x.data.as_ref()).collect();

        for (namespace, range) in tree.namespace_ranges.clone().iter() {
            let proof = tree.build_range_proof(range.clone());

            assert!(tree
                .verify_namespace(&root, &raw_leaves[range.clone()], *namespace, proof,)
                .is_ok());
        }
    }
}
