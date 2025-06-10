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

type BoxedVisitor<M> = Box<dyn Fn(&<M as MerkleHash>::Output) + Send>;

/// Helper data structure for immutable data used during proof narrowing recursion.
/// All indices are relative to the leaves of the entire tree.
struct ProofNarrowingParams<'a, M: MerkleHash> {
    /// All the leaves inside the old proof range, but to the left of the new (desired) proof range
    left_extra_leaves: &'a [M::Output],
    /// The start and end indices of the final, narrower proven range.
    narrowed_leaf_range: Range<usize>,
    /// All the leaves inside the old proof range, but to the right of the new (desired) proof range
    right_extra_leaves: &'a [M::Output],
    /// The starting index (w.r.t. the tree's leaves) of the old proof; equivalently, the index of
    /// the first leaf in left_extra_leaves
    leaves_start_idx: usize,
}

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

    /// Helper for the proof narrowing operation.
    ///
    /// # Arguments:
    /// - params: the immutable data used during recursion
    /// - working_range: The range of leaf indices, relative to the entire tree, being currently
    ///   considered. Recursion starts with Range(0..tree_size).
    /// - current_proof: A slice containing the proof of the current, wide range. The slice is
    ///   mutable as the recursion consumes nodes from it and copies them to the output proof.
    /// - out: will contain the new proof after recursion finishes
    fn narrow_range_proof_inner(
        &self,
        params: &ProofNarrowingParams<M>,
        working_range: Range<usize>,
        current_proof: &mut &[M::Output],
        out: &mut Vec<M::Output>,
    ) -> Result<(), RangeProofError> {
        // Sanity check. This will always be true because:
        // - At the top level, the working_range is the tree size, and we handle sizes 0 and 1 as
        // special cases
        // - When recursing, working_range of length 1 is a base case (we just return the leaf),
        // so we will never recurse on it
        assert!(working_range.len() > 1);

        let split_point = next_smaller_po2(working_range.len()) + working_range.start;

        // If the left subtree doesn't overlap with the new leaf, get its root and add it to the proof
        if params.narrowed_leaf_range.start >= (split_point) {
            let sibling = self.partial_tree_subroot_inner(
                working_range.start..split_point,
                current_proof,
                params.left_extra_leaves,
                params.leaves_start_idx,
            )?;
            out.push(sibling.clone());
        } else {
            let subtree_size = split_point - working_range.start;
            assert!(subtree_size > 0); // sanity check: since working_range > 1, each sub-tree must be >= 1
            if subtree_size == 1 {
                // If it's a leaf, do nothing
                let index = working_range.start;
                // Sanity check: if this fails, there's a bug in calculating the range limits and
                // indices somewhere
                assert!(params.narrowed_leaf_range.contains(&index));
            } else {
                // Else, recurse
                self.narrow_range_proof_inner(
                    params,
                    working_range.start..split_point,
                    current_proof,
                    out,
                )?;
            }
        }

        // If the right subtree doesn't overlap with the new leaf, get its root and add it to the proof
        if params.narrowed_leaf_range.end <= (split_point) {
            let right_leaves_start_idx = params
                .leaves_start_idx
                .checked_add(params.left_extra_leaves.len())
                .and_then(|i| i.checked_add(params.narrowed_leaf_range.len()))
                .ok_or(RangeProofError::TreeTooLarge)?;
            let sibling = self.partial_tree_subroot_inner(
                split_point..working_range.end,
                current_proof,
                params.right_extra_leaves,
                right_leaves_start_idx,
            )?;
            out.push(sibling.clone());
        } else {
            let subtree_size = working_range.end - split_point;
            assert!(subtree_size > 0); // sanity check - see left subtree explanation
            if subtree_size == 1 {
                // If it's a leaf, do nothing
                let index = split_point;
                assert!(params.narrowed_leaf_range.contains(&index)); // sanity check - see left subtree explanation
            } else {
                // Else, recurse
                self.narrow_range_proof_inner(
                    params,
                    split_point..working_range.end,
                    current_proof,
                    out,
                )?;
            }
        }

        Ok(())
    }

    /// To be used during the narrowing operation
    /// Calculates a new subroot to be part of the narrowed proof,
    /// in an area covered by the old proof and new leaves.
    ///
    /// All indices are relative to the entire tree.
    ///
    /// # Arguments
    ///  - subtree_range: The indices (in the tree) of the leaves of the subtree that we're
    ///    calculating the subroot of.
    ///  - extra_leaves: One of the two sets of hashes supplied by the user to narrow down the
    ///    proof range. Because the two sets are discontiguous, one on each side of the desired new
    ///    narrower range, only one set at a time is relevant here.
    ///  - leaves_start_idx: The start of the extra_leaves (relative to the tree). When calculating
    ///    subroots to the left of the narrowed range (i.e. extra_leaves == left_extra_leaves), this will
    ///    simply be the (original) proof's start_idx; when calculating subroots to the right, this will
    ///    be offset correspondingly (i.e. original_start_idx + left_extra_leaves.len() + desired_range_size.len()).
    fn partial_tree_subroot_inner(
        &self,
        subtree_range: Range<usize>,
        current_proof: &mut &[M::Output],
        extra_leaves: &[M::Output],
        leaves_start_idx: usize,
    ) -> Result<M::Output, RangeProofError> {
        // Helper that essentially replicates `compute_root`, but with no side-effects and with
        // only a partial leaf set
        struct SubrootParams<'a, M: MerkleHash> {
            extra_leaves: &'a [M::Output],
            leaves_start_idx: usize,
            hasher: &'a M,
        }
        fn local_subroot_from_leaves<M: MerkleHash>(
            range: Range<usize>,
            params: &SubrootParams<M>,
        ) -> Result<M::Output, RangeProofError> {
            if range.len() == 1 {
                params
                    .extra_leaves
                    .get(range.start - params.leaves_start_idx)
                    .ok_or(RangeProofError::MissingLeaf)
                    .cloned()
            } else {
                let split_point = next_smaller_po2(range.len()) + range.start;
                let left = local_subroot_from_leaves(range.start..split_point, params)?;
                let right = local_subroot_from_leaves(split_point..range.end, params)?;
                Ok(params.hasher.hash_nodes(&left, &right))
            }
        }

        // We are operating on a full subtree. So the base cases are (where _ is an unknown leaf,
        // and # is a leaf included in extra_leaves):
        //
        // [####] - the added leaves are covering the entire range; use them to calculate the subroot
        // [____] - there are no added leaves in the range; there is an existing proof node for this entire subtree
        // In all other cases, we split as normal and recurse on both subtrees.
        //
        // For example:
        // [___#] - We recurse on the two sub-trees [__] and [_#]. The left one will correspond to
        // a single proof node hashing both leaves. On the right one, we recurse again
        // into [_] and [#]. The left one is a single leaf and must also have been included in the
        // proof; the right one was part of the old proved range, and now supplied as part of
        // extra_leaves. Now we can hash these two together, and then hash it with the known parent of
        // the unknown left two nodes to obtain the root for the 4-wide subtree.

        let leaves_end_idx = leaves_start_idx + extra_leaves.len();
        if leaves_start_idx <= subtree_range.start && leaves_end_idx >= subtree_range.end {
            local_subroot_from_leaves(
                subtree_range,
                &SubrootParams {
                    extra_leaves,
                    leaves_start_idx,
                    hasher: &self.hasher,
                },
            )
        } else if leaves_start_idx >= subtree_range.end || leaves_end_idx <= subtree_range.start {
            return current_proof
                .slice_take_first()
                .ok_or(RangeProofError::MissingProofNode)
                .cloned();
        } else {
            // Sanity check. Both in narrow_range_proof_inner and here, we never recurse on ranges
            // < 2, as those are base cases (we return the leaves directly).
            assert!(subtree_range.len() > 1);

            let split_point = next_smaller_po2(subtree_range.len()) + subtree_range.start;
            let left = self.partial_tree_subroot_inner(
                subtree_range.start..split_point,
                current_proof,
                extra_leaves,
                leaves_start_idx,
            )?;
            let right = self.partial_tree_subroot_inner(
                split_point..subtree_range.end,
                current_proof,
                extra_leaves,
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
    /// a new proof for a subrange of the original proof's range.
    ///
    /// Effectively, we have two ranges of leaves provided, which can make the range narrower from
    /// the left or the right respectively (alongside the original proof). The high level logic of
    /// building a proof out of that is very similar to the normal build_range_proof logic, with
    /// two exceptions: we don't have the root (or most inner nodes), so we recurse based on the
    /// leaves and calculate the intermediate hashes we need as we go; and we don't have all the
    /// leaves either, so the partial_tree_subroot_inner function calculates inner node roots using
    /// information from both the original proof and the leaves we do have.
    ///
    /// Example: consider the following merkle tree with eight leaves:
    /// ```ascii
    ///                    root
    ///                /          \
    ///            A                  B
    ///         /    \             /    \
    ///       C        D         E        F
    ///      / \      /  \      / \      /  \
    ///     G   H    I    J    K   L    M    N
    ///
    /// ```
    /// A proof of [H, I, J, K] will contain nodes [G, L, F]. If we want to turn that into a proof
    /// of [J], that would need nodes [I, C, B].
    /// We recursively subdivide the total leaf range to find the subtrees that don't overlap the
    /// final desired range, just as in the normal build_range_proof - in this case, [G, H], [I],
    /// and [K, L, M, N]. We can then combine the information from the proof and the {left|right}_extra_leaves
    /// to calculate the subroots of each of those trees - for example, B = hash(E | F), where F is
    /// from the original proof, and E is calculated using K (from right_extra_leaves) and L (from
    /// the original proof). Thus we arrive at the new proof for the narrower range.
    pub fn narrow_range_proof(
        &mut self,
        left_extra_leaves: &[M::Output],
        narrowed_leaf_range: Range<usize>,
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
            .checked_add(narrowed_leaf_range.len())
            .ok_or(RangeProofError::TreeTooLarge)?
            .checked_add(right_extra_leaves.len())
            .ok_or(RangeProofError::TreeTooLarge)?;
        let tree_size =
            compute_tree_size(num_right_siblings, leaves_start_idx + current_leaf_size - 1)?;
        let mut proof = Vec::new();
        match tree_size {
            0 => {
                if !(current_proof.is_empty()
                    && left_extra_leaves.is_empty()
                    && right_extra_leaves.is_empty())
                {
                    return Err(RangeProofError::NoLeavesProvided);
                }
            }
            1 => {
                // For trees of size 1, the root is the only possible proof. An empty proof
                // is also valid (as the root is provided anyway when verifying).
                // As these are the only possible options and they are both valid,
                // there is nothing to be done when narrowing.
                proof = current_proof.to_vec();
            }
            _ => {
                self.narrow_range_proof_inner(
                    &ProofNarrowingParams {
                        left_extra_leaves,
                        narrowed_leaf_range: narrowed_leaf_range.clone(),
                        right_extra_leaves,
                        leaves_start_idx,
                    },
                    0..tree_size,
                    current_proof,
                    &mut proof,
                )?;
            }
        };
        Ok(Proof {
            siblings: proof,
            // TODO: is it really safe to convert usize to and from u32 everywhere in this library?
            range: narrowed_leaf_range.start as u32..narrowed_leaf_range.end as u32,
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
pub fn next_smaller_po2(int: usize) -> usize {
    // Calculate the first power of two which is greater than or equal to the argument, then divide by two.
    int.next_power_of_two() >> 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::simple_merkle::db::{MemDb};
    use crate::TmSha2Hasher;
    use hex;

    #[test]
    fn test_tree() {
        let mut tree: MerkleTree<MemDb<[u8; 32]>, TmSha2Hasher> = MerkleTree::new();
        tree.visitor = Box::new(|h| println!("{:?}", hex::encode(h)));
        for i in 1..17 {
            tree.push_raw_leaf(&[i as u8]);
        }
        let root = tree.root();
        assert_eq!(
            hex::encode(root),
            "451f071b539a1b912ead47ff3ba769147903a3a23a1d466f93656f4933934ca8"
        );
        println!(" ============ \n");
        println!("merkle root: {:?}", hex::encode(root));
        let proof = tree.get_index_with_proof(2);
        println!("index: {} merkle path ============ ", proof.1.range.start);
        proof
            .1
            .siblings
            .iter()
            .for_each(|h| println!("{:?}", hex::encode(h)));
    }
}
