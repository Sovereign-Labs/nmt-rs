use core::ops::Range;

use super::{
    db::NoopDb,
    error::RangeProofError,
    tree::{MerkleHash, MerkleTree},
    utils::compute_num_left_siblings,
};
use crate::maybestd::vec::Vec;

/// A proof of some statement about a namespaced merkle tree.
///
/// This proof may prove the presence of some set of leaves, or the
/// absence of a particular namespace
#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Proof<M: MerkleHash> {
    /// The siblings to be used to build the path to the root.
    pub siblings: Vec<M::Output>,
    /// The range of indices covered by the proof.
    pub range: Range<u32>,
}

impl<M: MerkleHash> Default for Proof<M> {
    fn default() -> Self {
        Self {
            siblings: Default::default(),
            range: Default::default(),
        }
    }
}

impl<M> Proof<M>
where
    M: MerkleHash + Default,
{
    /// Verify a range proof
    pub fn verify_range(
        &self,
        root: &M::Output,
        leaf_hashes: &[M::Output],
    ) -> Result<(), RangeProofError> {
        if leaf_hashes.len() != self.range_len() {
            return Err(RangeProofError::WrongAmountOfLeavesProvided);
        }

        let tree = MerkleTree::<NoopDb, M>::new();
        tree.check_range_proof(
            root,
            leaf_hashes,
            self.siblings(),
            self.start_idx() as usize,
        )
    }
}

impl<M> Proof<M>
where
    M: MerkleHash,
{
    /// Verify a range proof
    pub fn verify_range_with_hasher(
        &self,
        root: &M::Output,
        leaf_hashes: &[M::Output],
        hasher: M,
    ) -> Result<(), RangeProofError> {
        if leaf_hashes.len() != self.range_len() {
            return Err(RangeProofError::WrongAmountOfLeavesProvided);
        }

        let tree = MerkleTree::<NoopDb, M>::with_hasher(hasher);
        tree.check_range_proof(
            root,
            leaf_hashes,
            self.siblings(),
            self.start_idx() as usize,
        )
    }

    /// Narrows the proof range: uses an existing proof to create
    /// a new proof for a subrange of the original proof's range
    pub fn narrow_range_with_hasher(
        &self,
        left_extra_leaves: &[M::Output],
        right_extra_leaves: &[M::Output],
        hasher: M,
    ) -> Result<Self, RangeProofError> {
        let new_leaf_len = left_extra_leaves
            .len()
            .checked_add(right_extra_leaves.len())
            .ok_or(RangeProofError::TreeTooLarge)?;
        if new_leaf_len >= self.range_len() {
            return Err(RangeProofError::WrongAmountOfLeavesProvided);
        }
        let new_start_idx = (self.start_idx() as usize)
            .checked_add(left_extra_leaves.len())
            .ok_or(RangeProofError::TreeTooLarge)?;
        let new_end_idx = new_start_idx
            .checked_add(self.range_len())
            .and_then(|i| i.checked_sub(new_leaf_len))
            .ok_or(RangeProofError::TreeTooLarge)?;

        let mut tree = MerkleTree::<NoopDb, M>::with_hasher(hasher);
        tree.narrow_range_proof(
            left_extra_leaves,
            new_start_idx..new_end_idx,
            right_extra_leaves,
            &mut self.siblings().as_slice(),
            self.start_idx() as usize,
        )
    }

    /// Returns the siblings provided as part of the proof.
    pub fn siblings(&self) -> &Vec<M::Output> {
        &self.siblings
    }

    /// Returns the index of the first leaf covered by the proof.
    pub fn start_idx(&self) -> u32 {
        self.range.start
    }

    /// Returns the index *after* the last leaf included in the proof.
    pub fn end_idx(&self) -> u32 {
        self.range.end
    }

    /// Returns the length of the range covered by the proof.
    pub fn range_len(&self) -> usize {
        self.range.end.saturating_sub(self.range.start) as usize
    }

    /// Returns the leftmost node to the right of the proven range, if one exists.
    pub fn leftmost_right_sibling(&self) -> Option<&M::Output> {
        let siblings = self.siblings();
        let num_left_siblings = compute_num_left_siblings(self.start_idx() as usize);
        if siblings.len() > num_left_siblings {
            return Some(&siblings[num_left_siblings]);
        }
        None
    }

    /// Returns the rightmost node to the left of the proven range, if one exists.
    pub fn rightmost_left_sibling(&self) -> Option<&M::Output> {
        let siblings = self.siblings();
        let num_left_siblings = compute_num_left_siblings(self.start_idx() as usize);
        if num_left_siblings != 0 && num_left_siblings <= siblings.len() {
            return Some(&siblings[num_left_siblings - 1]);
        }
        None
    }
}
