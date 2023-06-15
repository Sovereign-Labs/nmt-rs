use super::{
    db::MemDb,
    error::RangeProofError,
    tree::{MerkleHash, MerkleTree},
    utils::compute_num_left_siblings,
};

/// A proof of some statement about a namespaced merkle tree.
///
/// This proof may prove the presence of some set of leaves, or the
/// absence of a particular namespace
#[derive(Debug, PartialEq, Clone, Default)]
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Proof<M: MerkleHash> {
    pub siblings: Vec<M::Output>,
    pub start_idx: u32,
}

impl<M> Proof<M>
where
    M: MerkleHash,
{
    /// Verify a range proof
    pub fn verify_range(
        mut self,
        root: &M::Output,
        leaf_hashes: &[M::Output],
    ) -> Result<(), RangeProofError> {
        let tree = MerkleTree::<MemDb<M::Output>, M>::new();

        tree.check_range_proof(
            root,
            leaf_hashes,
            &mut self.siblings,
            self.start_idx as usize,
        )?;
        Ok(())
    }

    pub fn siblings(&self) -> &Vec<M::Output> {
        &self.siblings
    }

    pub fn start_idx(&self) -> u32 {
        self.start_idx
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

    #[cfg(test)]
    pub fn take_siblings(self) -> Vec<M::Output> {
        self.siblings
    }
}
