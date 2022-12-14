#![feature(slice_take)]
use std::{collections::HashMap, hash::Hash, ops::Range};

use sha2::{Digest, Sha256};

const HASH_LEN: usize = 32;
const NAMESPACE_ID_LEN: usize = 8;
const NAMESPACED_HASH_LEN: usize = HASH_LEN + 2 * NAMESPACE_ID_LEN;
pub type Hasher = Sha256;

pub const LEAF_DOMAIN_SEPARATOR: [u8; 1] = [0u8];
pub const INTERNAL_NODE_DOMAIN_SEPARATOR: [u8; 1] = [1u8];

#[derive(Debug, PartialEq, PartialOrd, Eq, Ord, Copy, Clone, Hash)]
pub struct NamespaceId(pub [u8; NAMESPACE_ID_LEN]);

impl AsRef<[u8]> for NamespaceId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
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
        let mut out = Self([0u8; NAMESPACED_HASH_LEN]);
        out.set_hash(Hasher::new().finalize().as_ref());
        out
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
pub struct LeafWithHash {
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
            root: Some(NamespacedHash::empty()),
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
            assert_eq!(&subtrie_root, &NamespacedHash::empty());
            return out.push(subtrie_root);
        }
    }

    fn check_range_proof_inner(
        &self,
        root: &NamespacedHash,
        leaves: &mut &[LeafWithHash],
        mut proof: &mut Vec<NamespacedHash>,
        leaves_start_idx: usize,
        subtrie_size: usize,
        offset: usize,
    ) -> Result<NamespacedHash, RangeProofError> {
        let split_point = next_smaller_po2(subtrie_size);

        let leaves_end_idx = (leaves.len() + leaves_start_idx) - 1;
        // If there's a node in the right subtree
        let right = if leaves_end_idx >= (split_point + offset) {
            let right_subtrie_size = subtrie_size - split_point;
            if right_subtrie_size == 1 {
                leaves
                    .take_last()
                    .ok_or(RangeProofError::MissingLeaf)?
                    .hash
                    .clone()
            } else {
                // Recurse right
                self.check_range_proof_inner(
                    root,
                    leaves,
                    &mut proof,
                    leaves_start_idx,
                    right_subtrie_size,
                    offset + split_point,
                )?
            }
        } else {
            proof.pop().ok_or(RangeProofError::MissingProofNode)?
        };

        let left = if leaves_start_idx < (split_point + offset) {
            let left_subtrie_size = split_point;
            if left_subtrie_size == 1 {
                leaves
                    .take_last()
                    .ok_or(RangeProofError::MissingLeaf)?
                    .hash
                    .clone()
            } else {
                // Recurse left
                self.check_range_proof_inner(
                    root,
                    leaves,
                    &mut proof,
                    leaves_start_idx,
                    left_subtrie_size,
                    offset,
                )?
            }
        } else {
            proof.pop().ok_or(RangeProofError::MissingProofNode)?
        };

        Ok(self.hash_nodes(left, right))
    }

    pub fn check_range_proof(
        &self,
        root: NamespacedHash,
        leaves: &[LeafWithHash],
        proof: &mut Vec<NamespacedHash>,
        leaves_start_idx: usize,
    ) -> Result<(), RangeProofError> {
        if root == NamespacedHash::empty() {
            if leaves.len() == 0 && leaves_start_idx == 0 && proof.len() == 0 {
                return Ok(());
            }
            return Err(RangeProofError::TreeIsEmpty);
        }

        // Cannot range prove an empty range
        if leaves.len() <= 0 {
            return Err(RangeProofError::NoLeavesProvided);
        }

        if leaves.len() == 1 && proof.len() == 0 {
            if leaves[0].hash == root && leaves_start_idx == 0 {
                return Ok(());
            }
            return Err(RangeProofError::TreeDoesNotContainLeaf);
        }

        // Do binary decomposition magic to reconstruct the size of the binary tree
        // from the proof
        let tree_size = {
            // The number of left siblings is the number of ones in the binary
            // decomposition of the start index
            let mut num_left_siblings = 0;
            let mut start_idx = leaves_start_idx;
            while start_idx != 0 {
                if start_idx & 1 != 0 {
                    num_left_siblings += 1;
                }
                start_idx >>= 1;
            }

            // Each right sibling adds a `1` at the least significant place of the index_of_final_node which
            // would still have been a zero without that sibling.
            let mut index_of_final_node = leaves_start_idx + leaves.len() - 1;
            let mut remaining_right_siblings = proof.len() - num_left_siblings;
            let mut mask = 1;
            while remaining_right_siblings > 0 && index_of_final_node < u32::MAX as usize {
                if index_of_final_node & mask == 0 {
                    index_of_final_node |= mask;
                    remaining_right_siblings -= 1;
                }
                mask <<= 1;
            }
            index_of_final_node + 1
        };

        let computed_root = self.check_range_proof_inner(
            &root,
            &mut &leaves[..],
            proof,
            leaves_start_idx,
            tree_size,
            0,
        )?;
        if computed_root == root {
            return Ok(());
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
    pub fn build_range_proof(&mut self, leaf_range: Range<usize>) -> Vec<NamespacedHash> {
        if leaf_range.len() == 0 {
            return vec![];
        }
        // Calculate the root to ensure that the preimage db is populated
        let root = self.root();
        let mut proof = Vec::new();
        // self.build_range_proof_inner(leaf_range, 0..self.leaves.len())
        self.build_range_proof_inner(leaf_range, root, 0..self.leaves.len(), &mut proof);
        proof
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
}

#[cfg(test)]
mod tests {
    use crate::{MemDb, NamespaceMerkleTree};

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
    fn test_tree_with_n_leaves(n: usize) {
        let mut tree = tree_with_n_leaves(n);
        let root = tree.root();
        for i in 1..=n {
            for j in 0..i {
                let mut proof = tree.build_range_proof(j..i);
                let leaves = &mut &tree.leaves[j..i];
                let res = tree.check_range_proof(root.clone(), leaves, &mut proof, j);
                assert!(res.is_ok())
            }
        }
    }
    #[test]
    fn test_x_leaves() {
        for x in 0..20 {
            test_tree_with_n_leaves(x)
        }
    }
}
