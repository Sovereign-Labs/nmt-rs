use super::db::{LeafWithHash, Node, PreimageDb};
use super::error::RangeProofError;
use super::proof::Proof;
use super::utils::{compute_num_left_siblings, compute_tree_size};
use crate::maybestd::{boxed::Box, fmt::Debug, hash::Hash, ops::Range, vec::Vec};

/// Manually implement the method we need from #[feature(slice_take)] to
/// allow building with stable;
trait TakeLast<T> {
    fn slice_take_last<'a>(self: &mut &'a Self) -> Option<&'a T>;
}

impl<T> TakeLast<T> for [T] {
    fn slice_take_last<'a>(self: &mut &'a Self) -> Option<&'a T> {
        let (last, rem) = self.split_last()?;
        *self = rem;
        Some(last)
    }
}

trait TakeFirst<T> {
    fn slice_take_first<'a>(self: &mut &'a Self) -> Option<&'a T>;
}

impl<T> TakeFirst<T> for [T] {
    fn slice_take_first<'a>(self: &mut &'a Self) -> Option<&'a T> {
        let (first, rem) = self.split_first()?;
        *self = rem;
        Some(first)
    }
}

type BoxedVisitor<M> = Box<dyn Fn(&<M as MerkleHash>::Output)>;

/// Implements an RFC 6962 compatible merkle tree over an in-memory data store which maps preimages to hashes.
pub struct MerkleTree<Db, M>
where
    M: MerkleHash,
{
    leaves: Vec<LeafWithHash<M>>,
    db: Db,
    root: Option<M::Output>,
    visitor: BoxedVisitor<M>,
    hasher: M,
}

impl<Db: PreimageDb<<M as MerkleHash>::Output>, M: MerkleHash + Default> Default
    for MerkleTree<Db, M>
{
    fn default() -> Self {
        Self {
            leaves: Default::default(),
            db: Default::default(),
            root: Default::default(),
            visitor: Box::new(|_| {}),
            hasher: Default::default(),
        }
    }
}

/// A trait for hashing data into a merkle tree
pub trait MerkleHash {
    // --- no-std
    /// The output of this hasher.
    #[cfg(all(not(feature = "serde"), not(feature = "borsh"), not(feature = "std")))]
    type Output: Debug + PartialEq + Eq + Clone + Default + Hash;

    /// The output of this hasher.
    #[cfg(all(feature = "serde", not(feature = "borsh"), not(feature = "std")))]
    type Output: Debug
        + PartialEq
        + Eq
        + Clone
        + Default
        + Hash
        + serde::Serialize
        + serde::de::DeserializeOwned;

    /// The output of this hasher.
    #[cfg(all(feature = "borsh", not(feature = "serde"), not(feature = "std")))]
    type Output: Debug
        + PartialEq
        + Eq
        + Clone
        + Default
        + Hash
        + borsh::BorshSerialize
        + borsh::BorshDeserialize;

    /// The output of this hasher.
    #[cfg(all(feature = "borsh", feature = "serde", not(feature = "std")))]
    type Output: Debug
        + PartialEq
        + Eq
        + Clone
        + Default
        + Hash
        + borsh::BorshSerialize
        + borsh::BorshDeserialize
        + serde::Serialize
        + serde::de::DeserializeOwned;

    // --- std
    /// The output of this hasher.
    #[cfg(all(not(feature = "serde"), not(feature = "borsh"), feature = "std"))]
    type Output: Debug + PartialEq + Eq + Clone + Default + Hash + Ord;

    /// The output of this hasher.
    #[cfg(all(feature = "serde", not(feature = "borsh"), feature = "std"))]
    type Output: Debug
        + PartialEq
        + Eq
        + Clone
        + Default
        + Hash
        + Ord
        + serde::Serialize
        + serde::de::DeserializeOwned;

    /// The output of this hasher.
    #[cfg(all(not(feature = "serde"), feature = "borsh", feature = "std"))]
    type Output: Debug
        + PartialEq
        + Eq
        + Clone
        + Default
        + Hash
        + Ord
        + borsh::BorshSerialize
        + borsh::BorshDeserialize;

    /// The output of this hasher.
    #[cfg(all(feature = "serde", feature = "borsh", feature = "std"))]
    type Output: Debug
        + PartialEq
        + Eq
        + Clone
        + Default
        + Hash
        + Ord
        + serde::Serialize
        + serde::de::DeserializeOwned
        + borsh::BorshSerialize
        + borsh::BorshDeserialize;

    /// The hash of the empty tree. This is often defined as the hash of the empty string.
    const EMPTY_ROOT: Self::Output;

    /// Hashes data as a "leaf" of the tree. This operation *should* be domain separated.
    fn hash_leaf(&self, data: &[u8]) -> Self::Output;
    /// Hashes two digests into one. This operation *should* be domain separated.
    fn hash_nodes(&self, l: &Self::Output, r: &Self::Output) -> Self::Output;
}

impl<Db, M> MerkleTree<Db, M>
where
    Db: PreimageDb<M::Output>,
    M: MerkleHash + Default,
{
    /// Constructs an empty merkle tree with a default hasher
    pub fn new() -> Self {
        Self::with_hasher(Default::default())
    }
}

impl<Db, M> MerkleTree<Db, M>
where
    Db: PreimageDb<M::Output>,
    M: MerkleHash,
{
    /// Constructs an empty merkle tree with the given hasher
    pub fn with_hasher(hasher: M) -> Self {
        Self {
            leaves: Vec::new(),
            db: Default::default(),
            root: Some(M::EMPTY_ROOT),
            visitor: Box::new(|_| {}),
            hasher,
        }
    }

    /// Appends the given leaf to the tree
    pub fn push_raw_leaf(&mut self, raw_leaf: &[u8]) {
        let leaf = LeafWithHash::with_hasher(raw_leaf.to_vec(), &self.hasher);
        self.push_leaf_with_hash(leaf);
    }

    /// Appends a pre-hashed leaf to the tree
    pub fn push_leaf_with_hash(&mut self, leaf_with_hash: LeafWithHash<M>) {
        self.root = None;
        self.leaves.push(leaf_with_hash);
    }

    /// Returns the root of the tree, computing it if necessary. Repeated queries return a cached result.
    pub fn root(&mut self) -> M::Output {
        if let Some(inner) = &self.root {
            return inner.clone();
        }
        let inner = self.compute_root(0..self.leaves.len());
        self.root = Some(inner.clone());
        inner
    }

    /// Returns the requested range of leaves
    pub fn get_leaves(&self, range: Range<usize>) -> Vec<Vec<u8>> {
        let leaves = &self.leaves[range];
        leaves.iter().map(|leaf| leaf.data().to_vec()).collect()
    }

    /// Returns all leaves in the tree
    pub fn leaves(&self) -> &[LeafWithHash<M>] {
        &self.leaves[..]
    }

    fn compute_root(&mut self, leaf_range: Range<usize>) -> M::Output {
        match leaf_range.len() {
            0 => {
                let root = M::EMPTY_ROOT;
                (self.visitor)(&root);
                root
            }
            1 => {
                let leaf_with_hash = &self.leaves[leaf_range.start];
                let root = leaf_with_hash.hash().clone();
                (self.visitor)(&root);
                self.db
                    .put(root.clone(), Node::Leaf(leaf_with_hash.data().to_vec()));
                root
            }
            _ => {
                let split_point = next_smaller_po2(leaf_range.len()) + leaf_range.start;
                let left = self.compute_root(leaf_range.start..split_point);
                let right = self.compute_root(split_point..leaf_range.end);
                let root = self.hasher.hash_nodes(&left, &right);
                (self.visitor)(&root);
                self.db.put(root.clone(), Node::Inner(left, right));
                root
            }
        }
    }

    fn build_range_proof_inner(
        &self,
        range_to_prove: Range<usize>,
        subtrie_root: M::Output,
        subtrie_range: Range<usize>,
        out: &mut Vec<M::Output>,
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
                            out,
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
                            out,
                        );
                    }
                }
            }
        } else {
            assert_eq!(&subtrie_root, &M::EMPTY_ROOT);
            out.push(subtrie_root)
        }
    }

    fn check_range_proof_inner(
        &self,
        leaves: &mut &[M::Output],
        proof: &mut &[M::Output],
        leaves_start_idx: usize,
        subtrie_size: usize,
        offset: usize,
    ) -> Result<M::Output, RangeProofError> {
        let split_point = next_smaller_po2(subtrie_size);

        let leaves_end_idx = (leaves.len() + leaves_start_idx) - 1;

        // If the leaf range overlaps with the right subtree
        let right = if leaves_end_idx >= (split_point + offset) {
            let right_subtrie_size = subtrie_size - split_point;
            // If the right subtree contains only a single node, it must be the last remaining leaf
            if right_subtrie_size == 1 {
                leaves
                    .slice_take_last()
                    .ok_or(RangeProofError::MissingLeaf)?
                    .clone()
            } else {
                // Recurse right
                self.check_range_proof_inner(
                    leaves,
                    proof,
                    leaves_start_idx,
                    right_subtrie_size,
                    offset + split_point,
                )?
            }
        } else {
            // Otherwise (if the leaf range doesn't overlap with the right subtree),
            // the sibling node must have been included in the range proof
            proof
                .slice_take_last()
                .ok_or(RangeProofError::MissingProofNode)?
                .clone()
        };

        // Similarly, // If the leaf range overlaps with the left subtree
        let left = if leaves_start_idx < (split_point + offset) {
            let left_subtrie_size = split_point;
            // If the right subtree contains only a single node, it must be the last remaining leaf
            if left_subtrie_size == 1 {
                leaves
                    .slice_take_last()
                    .ok_or(RangeProofError::MissingLeaf)?
                    .clone()
            } else {
                // Recurse left
                self.check_range_proof_inner(
                    leaves,
                    proof,
                    leaves_start_idx,
                    left_subtrie_size,
                    offset,
                )?
            }
        } else {
            // Otherwise (if the leaf range doesn't overlap with the right subtree),
            // the sibling node must have been included in the range proof
            proof
                .slice_take_last()
                .ok_or(RangeProofError::MissingProofNode)?
                .clone()
        };

        Ok(self.hasher.hash_nodes(&left, &right))
    }

    #[allow(clippy::too_many_arguments)]
    fn narrow_range_proof_inner(
        &self,
        working_range: Range<usize>,
        left_extra_leaves: &[M::Output],
        new_leaf_range: &Range<usize>,
        right_extra_leaves: &[M::Output],
        current_proof: &mut &[M::Output],
        leaves_start_idx: usize,
        out: &mut Vec<M::Output>,
    ) -> Result<(), RangeProofError> {
        assert!(working_range.len() > 1); // sanity check
        let split_point = next_smaller_po2(working_range.len()) + working_range.start;

        // If the left subtree doesn't overlap with the new leaf, get its root and add it to the proof
        if new_leaf_range.start >= (split_point) {
            let sibling = self.partial_tree_subroot_inner(
                working_range.start..split_point,
                left_extra_leaves,
                current_proof,
                leaves_start_idx,
            )?;
            out.push(sibling.clone());
        } else {
            let subtrie_size = split_point - working_range.start;
            assert!(subtrie_size > 0); // sanity check
            if subtrie_size == 1 {
                // If it's a leaf, ensure we have it, and do nothing
                let index = working_range.start;
                assert!(new_leaf_range.contains(&index));
            } else {
                // Else, recurse
                self.narrow_range_proof_inner(
                    working_range.start..split_point,
                    left_extra_leaves,
                    new_leaf_range,
                    right_extra_leaves,
                    current_proof,
                    leaves_start_idx,
                    out,
                )?;
            }
        }

        // If the right subtree doesn't overlap with the new leaf, get its root and add it to the proof
        if new_leaf_range.end <= (split_point) {
            let right_leaves_start_idx = leaves_start_idx
                .checked_add(left_extra_leaves.len())
                .and_then(|i| i.checked_add(new_leaf_range.len()))
                .ok_or(RangeProofError::TreeTooLarge)?;
            let sibling = self.partial_tree_subroot_inner(
                split_point..working_range.end,
                right_extra_leaves,
                current_proof,
                right_leaves_start_idx,
            )?;
            out.push(sibling.clone());
        } else {
            let subtrie_size = working_range.end - split_point;
            assert!(subtrie_size > 0); // sanity check
            if subtrie_size == 1 {
                // If it's a leaf, ensure we have it, and do nothing
                let index = split_point;
                assert!(new_leaf_range.contains(&index));
            } else {
                // Else, recurse
                self.narrow_range_proof_inner(
                    split_point..working_range.end,
                    left_extra_leaves,
                    new_leaf_range,
                    right_extra_leaves,
                    current_proof,
                    leaves_start_idx,
                    out,
                )?;
            }
        }

        Ok(())
    }

    /// To be used during the narrowing operation
    /// Calculates a new subroot to be part of the narrowed proof,
    /// in an area covered by the old proof and new leaves
    fn partial_tree_subroot_inner(
        &self,
        subtrie_range: Range<usize>,
        extra_leaves: &[M::Output],
        current_proof: &mut &[M::Output],
        leaves_start_idx: usize,
    ) -> Result<M::Output, RangeProofError> {
        fn local_subroot_from_leaves<M: MerkleHash>(
            leaf_hashes: &[M::Output],
            leaves_start_idx: usize,
            range: Range<usize>,
            hasher: &M,
        ) -> Result<M::Output, RangeProofError> {
            if range.len() == 1 {
                return leaf_hashes
                    .get(range.start - leaves_start_idx)
                    .ok_or(RangeProofError::MissingLeaf)
                    .cloned();
            } else {
                let split_point = next_smaller_po2(range.len()) + range.start;
                let left = local_subroot_from_leaves(
                    leaf_hashes,
                    leaves_start_idx,
                    range.start..split_point,
                    hasher,
                )?;
                let right = local_subroot_from_leaves(
                    leaf_hashes,
                    leaves_start_idx,
                    split_point..range.end,
                    hasher,
                )?;
                Ok(hasher.hash_nodes(&left, &right))
            }
        }

        // We are operating on a full subtree. So the base cases are:
        // [####] - the added leaves are covering the entire range; use them to calculate the subroot
        // [____] - there are no added leaves in the range; there is an existing proof node for this subtree
        // In all other cases, we split as normal and recurse on both subtrees.

        let leaves_end_idx = leaves_start_idx + extra_leaves.len();
        if leaves_start_idx <= subtrie_range.start && leaves_end_idx >= subtrie_range.end {
            local_subroot_from_leaves(extra_leaves, leaves_start_idx, subtrie_range, &self.hasher)
        } else if leaves_start_idx >= subtrie_range.end || leaves_end_idx <= subtrie_range.start {
            return current_proof
                .slice_take_first()
                .ok_or(RangeProofError::MissingProofNode)
                .cloned();
        } else {
            assert!(subtrie_range.len() > 1); // sanity check
            let split_point = next_smaller_po2(subtrie_range.len()) + subtrie_range.start;
            let left = self.partial_tree_subroot_inner(
                subtrie_range.start..split_point,
                extra_leaves,
                current_proof,
                leaves_start_idx,
            )?;
            let right = self.partial_tree_subroot_inner(
                split_point..subtrie_range.end,
                extra_leaves,
                current_proof,
                leaves_start_idx,
            )?;
            return Ok(self.hasher.hash_nodes(&left, &right));
        }
    }

    /// Checks a given range proof
    pub fn check_range_proof(
        &self,
        root: &M::Output,
        leaves: &[M::Output],
        proof: &[M::Output],
        leaves_start_idx: usize,
    ) -> Result<(), RangeProofError> {
        // As an optimization, the internal call doesn't recurse into subtrees of size smaller than 2
        // so we need to ensure that the root has size 2 or greater.
        match leaves.len() {
            0 => {
                if root == &M::EMPTY_ROOT && proof.is_empty() {
                    return Ok(());
                }
                return Err(RangeProofError::NoLeavesProvided);
            }
            1 => {
                if proof.is_empty() {
                    if &leaves[0] == root && leaves_start_idx == 0 {
                        return Ok(());
                    }
                    return Err(RangeProofError::TreeDoesNotContainLeaf);
                }
            }
            _ => {}
        };

        let num_left_siblings = compute_num_left_siblings(leaves_start_idx);
        let num_right_siblings = proof
            .len()
            .checked_sub(num_left_siblings)
            .ok_or(RangeProofError::MissingProofNode)?;

        let tree_size = compute_tree_size(num_right_siblings, leaves_start_idx + leaves.len() - 1)?;

        let computed_root = self.check_range_proof_inner(
            &mut &leaves[..],
            &mut &proof[..],
            leaves_start_idx,
            tree_size,
            0,
        )?;
        if &computed_root == root {
            return Ok(());
        }
        Err(RangeProofError::InvalidRoot)
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
        // Calculate the root to ensure that the preimage db is populated
        let root = self.root();
        let mut proof = Vec::new();
        let start = leaf_range.start as u32;
        let end = leaf_range.end as u32;
        if leaf_range.end > self.leaves.len() {
            panic!(
                "Index out of range: cannot access leaf {} in leaves array of size {}",
                leaf_range.end,
                self.leaves.len()
            )
        }
        self.build_range_proof_inner(leaf_range, root, 0..self.leaves.len(), &mut proof);

        Proof {
            siblings: proof,
            range: start..end,
        }
    }

    /// Narrows the proof range: uses an existing proof to create
    /// a new proof for a subrange of the original proof's range
    pub fn narrow_range_proof(
        &mut self,
        left_extra_leaves: &[M::Output],
        new_leaf_range: Range<usize>,
        right_extra_leaves: &[M::Output],
        current_proof: &mut &[M::Output],
        leaves_start_idx: usize,
    ) -> Result<Proof<M>, RangeProofError> {
        let num_left_siblings = compute_num_left_siblings(leaves_start_idx);
        let num_right_siblings = current_proof
            .len()
            .checked_sub(num_left_siblings)
            .ok_or(RangeProofError::MissingProofNode)?;

        let current_leaf_size = left_extra_leaves
            .len()
            .checked_add(new_leaf_range.len())
            .ok_or(RangeProofError::TreeTooLarge)?
            .checked_add(right_extra_leaves.len())
            .ok_or(RangeProofError::TreeTooLarge)?;
        let tree_size =
            compute_tree_size(num_right_siblings, leaves_start_idx + current_leaf_size - 1)?;
        let mut proof = Vec::new();
        self.narrow_range_proof_inner(
            0..tree_size,
            left_extra_leaves,
            &new_leaf_range,
            right_extra_leaves,
            current_proof,
            leaves_start_idx,
            &mut proof,
        )?;
        Ok(Proof {
            siblings: proof,
            // TODO: is it really safe to convert usize to and from u32 everywhere in this library?
            range: new_leaf_range.start as u32..new_leaf_range.end as u32,
        })
    }

    /// Fetches the requested range of leaves, along with a proof of correctness.
    pub fn get_range_with_proof(&mut self, leaf_range: Range<usize>) -> (Vec<Vec<u8>>, Proof<M>) {
        let leaves = &self.leaves[leaf_range.clone()];
        let leaves = leaves.iter().map(|leaf| leaf.data().to_vec()).collect();
        (leaves, self.build_range_proof(leaf_range))
    }

    /// Fetches the leaf at the given index, along with a proof of inclusion.
    pub fn get_index_with_proof(&mut self, idx: usize) -> (Vec<u8>, Proof<M>) {
        (
            self.leaves[idx].data().to_vec(),
            self.build_range_proof(idx..idx + 1),
        )
    }
}

/// Calculates the largest power of two which is strictly less than the argument
fn next_smaller_po2(int: usize) -> usize {
    // Calculate the first power of two which is greater than or equal to the argument, then divide by two.
    int.next_power_of_two() >> 1
}
