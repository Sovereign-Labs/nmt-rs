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
    pub siblings: Vec<M::Output>,
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

    pub fn siblings(&self) -> &Vec<M::Output> {
        &self.siblings
    }

    pub fn start_idx(&self) -> u32 {
        self.range.start
    }

    pub fn end_idx(&self) -> u32 {
        self.range.end
    }

    pub fn range_len(&self) -> usize {
        self.range.end.saturating_sub(self.range.start) as usize
    }

    pub fn leftmost_right_sibling(&self) -> Option<&M::Output> {
        let siblings = self.siblings();
        let num_left_siblings = compute_num_left_siblings(self.start_idx() as usize);
        if siblings.len() > num_left_siblings {
            return Some(&siblings[num_left_siblings]);
        }
        None
    }

    pub fn rightmost_left_sibling(&self) -> Option<&M::Output> {
        let siblings = self.siblings();
        let num_left_siblings = compute_num_left_siblings(self.start_idx() as usize);
        if num_left_siblings != 0 && num_left_siblings <= siblings.len() {
            return Some(&siblings[num_left_siblings - 1]);
        }
        None
    }
}
