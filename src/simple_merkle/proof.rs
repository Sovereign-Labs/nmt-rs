use core::{cmp::Ordering, ops::Range};

use super::{
    db::NoopDb,
    error::RangeProofError,
    tree::{MerkleHash, MerkleTree, next_smaller_po2},
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

    /// verify range with leaves data
    pub fn verify_with_leaves_data(
        &self,
        root: &M::Output,
        leaves_data: &[&[u8]],
    ) -> Result<(), RangeProofError> {
        if leaves_data.len() != self.range_len() {
            return Err(RangeProofError::WrongAmountOfLeavesProvided);
        }

        let hasher = M::default();
        let mut leaves_hash = vec![];
        leaves_data.iter().for_each(|x| { leaves_hash.push( hasher.hash_leaf(x))});
        self.verify_range(root, &leaves_hash)
    }
}

impl<M> Proof<M>
where
    M: MerkleHash,
{
    /// Create a new proof from a merkle path which generate by celestia
    pub fn from_celestia_merkle_path(
        merkle_path: &[M::Output],
        index: u32,
        total: u32,
    )  -> Self {
        let mut new_proof = vec![];
        Self::covert_merkle_path(merkle_path, &mut new_proof, index as usize, total as usize);
        let end = if total == 0{
            0
        }else {
            index+1
        };
        Self{
            siblings: new_proof,
            range:index..end,
        }
    }

    fn covert_merkle_path(
        merkle_path: &[M::Output],
        new_proof: &mut Vec<M::Output>,
        index: usize,
        total: usize,
    )  {
        // 只有一个Leaf的树merkle path为null
        if merkle_path.len() == 0{
            return;
        }
        // 基本案例：如果仅剩一个哈希，则返回
        if merkle_path.len() == 1 {
            new_proof.push(merkle_path[0].clone());
            return
        }

        // 计算拆分点
        let split_point = next_smaller_po2(total);
        // 递归处理左子树
        if index < split_point {
            Self::covert_merkle_path(
                &merkle_path[..merkle_path.len() - 1],
                new_proof,
                index,
                split_point,
            );
            // 在左子树之后添加当前节点
            new_proof.push(merkle_path[merkle_path.len() - 1].clone());
        } else {
            // 递归处理右子树
            new_proof.push(merkle_path[merkle_path.len() - 1].clone());
            Self::covert_merkle_path(
                &merkle_path[..merkle_path.len() - 1],
                new_proof,
                index - split_point,
                total - split_point,
            );
        }
    }

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
    ///
    /// # Arguments
    ///  - left_extra_leaves: The hashes of the leaves that will narrow the range from the left
    ///    side (i.e. all the leaves from the left edge of the currently proven range, to the left
    ///    edge of the new desired shrunk range)
    ///  - right_extra_leaves: Analogously, hashes of all the leaves between the right edge of
    ///    the desired shrunken range, and the right edge of the current proof's range
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
        match new_leaf_len.cmp(&self.range_len()) {
            Ordering::Equal => {
                // We cannot prove the empty range!
                return Err(RangeProofError::NoLeavesProvided);
            }
            Ordering::Greater => return Err(RangeProofError::WrongAmountOfLeavesProvided),
            Ordering::Less => { /* Ok! */ }
        }

        // Indices relative to the leaves of the entire tree
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::TmSha2Hasher;
    use hex;

    /**
     * TEST VECTORS
     *
     * 0x01
     * 0x02
     * 0x03
     * 0x04
     * 0x05
     * 0x06
     * 0x07
     * 0x08
     *
     *
     * 0xb413f47d13ee2fe6c845b2ee141af81de858df4ec549a58b7970bb96645bc8d2
     * 0xfcf0a6c700dd13e274b6fba8deea8dd9b26e4eedde3495717cac8408c9c5177f
     * 0x583c7dfb7b3055d99465544032a571e10a134b1b6f769422bbb71fd7fa167a5d
     * 0x4f35212d12f9ad2036492c95f1fe79baf4ec7bd9bef3dffa7579f2293ff546a4
     * 0x9f1afa4dc124cba73134e82ff50f17c8f7164257c79fed9a13f5943a6acb8e3d
     * 0x40d88127d4d31a3891f41598eeed41174e5bc89b1eb9bbd66a8cbfc09956a3fd
     * 0x2ecd8a6b7d2845546659ad4cf443533cf921b19dc81fa83934e83821b4dfdcb7
     * 0xb4c43b50bf245bd727623e3c775a8fcfb8d823d00b57dd65f7f79dd33f126315
     *
     * 0x6bcf0e2e93e0a18e22789aee965e6553f4fbe93f0acfc4a705d691c8311c4965
     * 0x78850a5ab36238b076dd99fd258c70d523168704247988a94caa8c9ccd056b8d
     * 0x90eeb2c4a04ec33ee4dd2677593331910e4203db4fcc120a6cdb95b13cfe83f0
     * 0x28c01722dd8dd05b63bcdeb6878bc2c083118cc2b170646d6b842d0bdbdc9d29
     *
     * 0xfa02d31a63cc11cc624881e52af14af7a1c6ab745efa71021cb24086b9b1793f
     * 0x4301a067262bbb18b4919742326f6f6d706099f9c0e8b0f2db7b88f204b2cf09
     *
     * 0xc1ad6548cb4c7663110df219ec8b36ca63b01158956f4be31a38a88d0c7f7071
     *
     */
    #[test]
    fn test_verify_none() {
        let root= TmSha2Hasher::EMPTY_ROOT;
        let siblings: Vec<[u8; 32]> = vec![];
        let proof = Proof::<TmSha2Hasher>::from_celestia_merkle_path(&siblings, 0, 0);
        let result = proof.verify_with_leaves_data(&root, &vec![]);
        assert!(result.is_ok());

        // let root = TmSha2Hasher::EMPTY_ROOT;
        // let proof = Proof::<TmSha2Hasher> {
        //     siblings: vec![],
        //     range: 0..0,
        // };
        // let result = proof.verify_with_leaves_data(&root, &[]);
        // assert!(result.is_err());
    }

    #[test]
    fn test_verify_one_leaf_empty() {
        let root:[u8;32]= hex::decode("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d").unwrap().try_into().unwrap();
        let siblings: Vec<[u8; 32]> = vec![];
        let proof = Proof::<TmSha2Hasher>::from_celestia_merkle_path(&siblings, 0, 1);
        let result =
            proof.verify_with_leaves_data(&root, &vec!["".as_bytes()]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_one_leaf_some() {
        let root:[u8;32]= hex::decode("48c90c8ae24688d6bef5d48a30c2cc8b6754335a8db21793cc0a8e3bed321729").unwrap().try_into().unwrap();
        let siblings: Vec<[u8; 32]> = vec![];
        let proof = Proof::<TmSha2Hasher>::from_celestia_merkle_path(&siblings, 0, 1);
        let result =
            proof.verify_with_leaves_data(&root, &vec![hex::decode("deadbeef").unwrap().as_slice()]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_one_leaf_01() {
        let root:[u8;32]= hex::decode("b413f47d13ee2fe6c845b2ee141af81de858df4ec549a58b7970bb96645bc8d2").unwrap().try_into().unwrap();
        let siblings: Vec<[u8; 32]> = vec![];
        let proof = Proof::<TmSha2Hasher>::from_celestia_merkle_path(&siblings, 0, 1);
        let result =
            proof.verify_with_leaves_data(&root, &vec![hex::decode("01").unwrap().as_slice()]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_leaf_one_of_eight() {
        let root:[u8;32]= hex::decode("c1ad6548cb4c7663110df219ec8b36ca63b01158956f4be31a38a88d0c7f7071").unwrap().try_into().unwrap();
        let mut siblings: Vec<[u8; 32]> = vec![];
        let merkle_path = vec![
            "fcf0a6c700dd13e274b6fba8deea8dd9b26e4eedde3495717cac8408c9c5177f",
            "78850a5ab36238b076dd99fd258c70d523168704247988a94caa8c9ccd056b8d",
            "4301a067262bbb18b4919742326f6f6d706099f9c0e8b0f2db7b88f204b2cf09",
        ];
        merkle_path.iter().for_each(|h| {
            siblings.push(hex::decode(h).unwrap().try_into().unwrap());
        });
        let proof = Proof::<TmSha2Hasher>::from_celestia_merkle_path(&siblings, 0, 8);
        let result =
            proof.verify_with_leaves_data(&root, &vec![hex::decode("01").unwrap().as_slice()]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_leaf_two_of_eight() {
        let root:[u8;32]= hex::decode("c1ad6548cb4c7663110df219ec8b36ca63b01158956f4be31a38a88d0c7f7071").unwrap().try_into().unwrap();
        let mut siblings: Vec<[u8; 32]> = vec![];
        let merkle_path = vec![
            "b413f47d13ee2fe6c845b2ee141af81de858df4ec549a58b7970bb96645bc8d2",
            "78850a5ab36238b076dd99fd258c70d523168704247988a94caa8c9ccd056b8d",
            "4301a067262bbb18b4919742326f6f6d706099f9c0e8b0f2db7b88f204b2cf09",
        ];
        merkle_path.iter().for_each(|h| {
            siblings.push(hex::decode(h).unwrap().try_into().unwrap());
        });
        let proof = Proof::<TmSha2Hasher>::from_celestia_merkle_path(&siblings, 1, 8);
        let result =
            proof.verify_with_leaves_data(&root, &vec![hex::decode("02").unwrap().as_slice()]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_leaf_three_of_eight() {
        let root:[u8;32]= hex::decode("c1ad6548cb4c7663110df219ec8b36ca63b01158956f4be31a38a88d0c7f7071").unwrap().try_into().unwrap();
        let mut siblings: Vec<[u8; 32]> = vec![];
        let merkle_path = vec![
            "4f35212d12f9ad2036492c95f1fe79baf4ec7bd9bef3dffa7579f2293ff546a4",
            "6bcf0e2e93e0a18e22789aee965e6553f4fbe93f0acfc4a705d691c8311c4965",
            "4301a067262bbb18b4919742326f6f6d706099f9c0e8b0f2db7b88f204b2cf09",
        ];
        merkle_path.iter().for_each(|h| {
            siblings.push(hex::decode(h).unwrap().try_into().unwrap());
        });
        let proof = Proof::<TmSha2Hasher>::from_celestia_merkle_path(&siblings, 2, 8);
        let result =
            proof.verify_with_leaves_data(&root, &vec![hex::decode("03").unwrap().as_slice()]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_leaf_seven_of_eight() {
        let root:[u8;32]= hex::decode("c1ad6548cb4c7663110df219ec8b36ca63b01158956f4be31a38a88d0c7f7071").unwrap().try_into().unwrap();
        let mut siblings: Vec<[u8; 32]> = vec![];
        let merkle_path = vec![
            "b4c43b50bf245bd727623e3c775a8fcfb8d823d00b57dd65f7f79dd33f126315",
            "90eeb2c4a04ec33ee4dd2677593331910e4203db4fcc120a6cdb95b13cfe83f0",
            "fa02d31a63cc11cc624881e52af14af7a1c6ab745efa71021cb24086b9b1793f",
        ];
        merkle_path.iter().for_each(|h| {
            siblings.push(hex::decode(h).unwrap().try_into().unwrap());
        });
        let proof = Proof::<TmSha2Hasher>::from_celestia_merkle_path(&siblings, 6, 8);
        let result =
            proof.verify_with_leaves_data(&root, &vec![hex::decode("07").unwrap().as_slice()]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_leaf_eight_of_eight() {
        let root:[u8;32]= hex::decode("c1ad6548cb4c7663110df219ec8b36ca63b01158956f4be31a38a88d0c7f7071").unwrap().try_into().unwrap();
        let mut siblings: Vec<[u8; 32]> = vec![];
        let merkle_path = vec![
            "2ecd8a6b7d2845546659ad4cf443533cf921b19dc81fa83934e83821b4dfdcb7",
            "90eeb2c4a04ec33ee4dd2677593331910e4203db4fcc120a6cdb95b13cfe83f0",
            "fa02d31a63cc11cc624881e52af14af7a1c6ab745efa71021cb24086b9b1793f",
        ];
        merkle_path.iter().for_each(|h| {
            siblings.push(hex::decode(h).unwrap().try_into().unwrap());
        });
        let proof = Proof::<TmSha2Hasher>::from_celestia_merkle_path(&siblings, 7, 8);
        let result =
            proof.verify_with_leaves_data(&root, &vec![hex::decode("08").unwrap().as_slice()]);
        assert!(result.is_ok());
    }

    // Test vectors:
    // 0x00
    // 0x01
    // 0x02
    // 0x03
    // 0x04
    #[test]
    fn test_verify_proof_of_five_leaves() {
        let root:[u8;32]= hex::decode("b855b42d6c30f5b087e05266783fbd6e394f7b926013ccaa67700a8b0c5a596f").unwrap().try_into().unwrap();
        let mut siblings: Vec<[u8; 32]> = vec![];
        let merkle_path = vec![
            "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
            "52c56b473e5246933e7852989cd9feba3b38f078742b93afff1e65ed46797825",
            "4f35212d12f9ad2036492c95f1fe79baf4ec7bd9bef3dffa7579f2293ff546a4",
        ];
        merkle_path.iter().for_each(|h| {
            siblings.push(hex::decode(h).unwrap().try_into().unwrap());
        });
        let proof = Proof::<TmSha2Hasher>::from_celestia_merkle_path(&siblings, 1, 5);
        let result =
            proof.verify_with_leaves_data(&root, &vec![hex::decode("01").unwrap().as_slice()]);
        assert!(result.is_ok())
    }

    #[test]
    fn test_verify_invalid_proof_root() {
        let root:[u8;32]= hex::decode("c855b42d6c30f5b087e05266783fbd6e394f7b926013ccaa67700a8b0c5a596f").unwrap().try_into().unwrap();
        let mut siblings: Vec<[u8; 32]> = vec![];
        let merkle_path = vec![
            "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
            "52c56b473e5246933e7852989cd9feba3b38f078742b93afff1e65ed46797825",
            "4f35212d12f9ad2036492c95f1fe79baf4ec7bd9bef3dffa7579f2293ff546a4",
        ];
        merkle_path.iter().for_each(|h| {
            siblings.push(hex::decode(h).unwrap().try_into().unwrap());
        });
        let proof = Proof::<TmSha2Hasher>::from_celestia_merkle_path(&siblings, 1, 5);
        let result =
            proof.verify_with_leaves_data(&root, &vec![hex::decode("01").unwrap().as_slice()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_invalid_proof_key() {
        let root:[u8;32]= hex::decode("b855b42d6c30f5b087e05266783fbd6e394f7b926013ccaa67700a8b0c5a596f").unwrap().try_into().unwrap();
        let mut siblings: Vec<[u8; 32]> = vec![];
        let merkle_path = vec![
            "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
            "52c56b473e5246933e7852989cd9feba3b38f078742b93afff1e65ed46797825",
            "4f35212d12f9ad2036492c95f1fe79baf4ec7bd9bef3dffa7579f2293ff546a4",
        ];
        merkle_path.iter().for_each(|h| {
            siblings.push(hex::decode(h).unwrap().try_into().unwrap());
        });
        let mut proof = Proof::<TmSha2Hasher>::from_celestia_merkle_path(&siblings, 1, 5);
        proof.range = 2..3;
        let result =
            proof.verify_with_leaves_data(&root, &vec![hex::decode("01").unwrap().as_slice()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_invalid_proof_side_nodes() {
        let root:[u8;32]= hex::decode("b855b42d6c30f5b087e05266783fbd6e394f7b926013ccaa67700a8b0c5a596f").unwrap().try_into().unwrap();
        let mut siblings: Vec<[u8; 32]> = vec![];
        let merkle_path = vec![
            "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
            "52c56b473e5246933e7852989cd9feba3b38f078742b93afff1e65ed46797825",
            // correct side node:"4f35212d12f9ad2036492c95f1fe79baf4ec7bd9bef3dffa7579f2293ff546a4",
            "5f35212d12f9ad2036492c95f1fe79baf4ec7bd9bef3dffa7579f2293ff546a4",
        ];
        merkle_path.iter().for_each(|h| {
            siblings.push(hex::decode(h).unwrap().try_into().unwrap());
        });
        let proof = Proof::<TmSha2Hasher>::from_celestia_merkle_path(&siblings, 1, 5);
        let result =
            proof.verify_with_leaves_data(&root, &vec![hex::decode("01").unwrap().as_slice()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_invalid_proof_data() {
        let root:[u8;32]= hex::decode("b855b42d6c30f5b087e05266783fbd6e394f7b926013ccaa67700a8b0c5a596f").unwrap().try_into().unwrap();
        let mut siblings: Vec<[u8; 32]> = vec![];
        let merkle_path = vec![
            "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
            "52c56b473e5246933e7852989cd9feba3b38f078742b93afff1e65ed46797825",
            "4f35212d12f9ad2036492c95f1fe79baf4ec7bd9bef3dffa7579f2293ff546a4",
        ];
        merkle_path.iter().for_each(|h| {
            siblings.push(hex::decode(h).unwrap().try_into().unwrap());
        });
        let proof = Proof::<TmSha2Hasher>::from_celestia_merkle_path(&siblings, 1, 5);
        let result =
            proof.verify_with_leaves_data(&root, &vec![hex::decode("012345").unwrap().as_slice()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_same_key_and_leaves_number() {
        let root: [u8; 32] =
            hex::decode("b855b42d6c30f5b087e05266783fbd6e394f7b926013ccaa67700a8b0c5a596f")
                .unwrap()
                .try_into()
                .unwrap();
        let proof = Proof::<TmSha2Hasher> {
            siblings: vec![],
            range: 3..4,
        };
        let result =
            proof.verify_with_leaves_data(&root, &vec![hex::decode("01").unwrap().as_slice()]);
        assert!(result.is_err())
    }

    #[test]
    fn test_consecutive_key_and_number_of_leaves() {
        let root: [u8; 32] =
            hex::decode("b855b42d6c30f5b087e05266783fbd6e394f7b926013ccaa67700a8b0c5a596f")
                .unwrap()
                .try_into()
                .unwrap();
        let proof = Proof::<TmSha2Hasher> {
            siblings: vec![],
            range: 6..7,
        };
        let result =
            proof.verify_with_leaves_data(&root, &vec![hex::decode("01").unwrap().as_slice()]);
        assert!(result.is_err())
    }

    // ================================================================
    //            Test for covert merkle path from celestia
    // ================================================================
    // merkle_path is generate from celestia.
    // Example code with golang:
    // ```go
    // import (
    // "github.com/tendermint/tendermint/crypto/merkle"
    // "fmt"
    // "hex"
    // )
    // func main() {
    // 	var leaves [][]byte
    // 	for i := 1; i < 17; i++ {
    // 		leaves = append(leaves, []byte{byte(i)})
    // 	}
    // 	root, proofs := merkle.ProofsFromByteSlices(leaves)
    // 	fmt.Println("root hash: ", hex.EncodeToString(root))
    //
    // 	fmt.Println("index 2 leaf for proof: ", hex.EncodeToString(proofs[2].LeafHash))
    // 	for i, v := range proofs[2].Aunts {
    // 		fmt.Printf("{%d} ==> %s\n", i, hex.EncodeToString(v))
    // 	}
    // ```
    // Note: replace github.com/tendermint/tendermint => github.com/celestiaorg/celestia-core v1.32.0-tm-v0.34.29 in go.mod.

    #[test]
    fn test_covert_8of16_celestia() {
        let root:[u8;32]= hex::decode("451f071b539a1b912ead47ff3ba769147903a3a23a1d466f93656f4933934ca8").unwrap().try_into().unwrap();
        let mut siblings: Vec<[u8; 32]> = vec![];
        let merkle_path = vec![
            "67ebbd370daa02ba9aadd05d8e091e862d0d8bcadafdf2a22360240a42fe922e",
            "4e0da3c379521af1f85d7eef03a7860cfe2dcb3efd8dd32194f0981f0f0af7d5",
            "0ed2ebf596a4de07fa95b19774c506b178cac53df3292bfd3908f85c2433995a",
            "c1ad6548cb4c7663110df219ec8b36ca63b01158956f4be31a38a88d0c7f7071",
        ];
        merkle_path.iter().for_each(|h| {
            siblings.push(hex::decode(h).unwrap().try_into().unwrap());
        });

        let proof = Proof::<TmSha2Hasher>::from_celestia_merkle_path(&siblings, 8, 16);
        let mut nmt_proof = Vec::new();
        proof.siblings
            .iter()
            .for_each(|h| nmt_proof.push(hex::encode(h)));
        let expect_proof = vec![
            "c1ad6548cb4c7663110df219ec8b36ca63b01158956f4be31a38a88d0c7f7071",
            "67ebbd370daa02ba9aadd05d8e091e862d0d8bcadafdf2a22360240a42fe922e",
            "4e0da3c379521af1f85d7eef03a7860cfe2dcb3efd8dd32194f0981f0f0af7d5",
            "0ed2ebf596a4de07fa95b19774c506b178cac53df3292bfd3908f85c2433995a",
        ];
        assert_eq!(expect_proof, nmt_proof);
        assert!(proof.verify_with_leaves_data(&root,&[&[9]]).is_ok())
    }
    #[test]
    fn test_covert_9of16_celestia() {
        let root:[u8;32]= hex::decode("451f071b539a1b912ead47ff3ba769147903a3a23a1d466f93656f4933934ca8").unwrap().try_into().unwrap();
        let mut siblings: Vec<[u8; 32]> = vec![];
        let merkle_path = vec![
            "c87479cd656e7e3ad6bd8db402e8027df454b2b0c42ff29e093458beb98a23d4",
            "4e0da3c379521af1f85d7eef03a7860cfe2dcb3efd8dd32194f0981f0f0af7d5",
            "0ed2ebf596a4de07fa95b19774c506b178cac53df3292bfd3908f85c2433995a",
            "c1ad6548cb4c7663110df219ec8b36ca63b01158956f4be31a38a88d0c7f7071",
        ];
        merkle_path.iter().for_each(|h| {
            siblings.push(hex::decode(h).unwrap().try_into().unwrap());
        });

        let proof = Proof::<TmSha2Hasher>::from_celestia_merkle_path(&siblings, 9, 16);
        let mut nmt_proof = Vec::new();
        proof.siblings
            .iter()
            .for_each(|h| nmt_proof.push(hex::encode(h)));
        let expect_proof = vec![
            "c1ad6548cb4c7663110df219ec8b36ca63b01158956f4be31a38a88d0c7f7071",
            "c87479cd656e7e3ad6bd8db402e8027df454b2b0c42ff29e093458beb98a23d4",
            "4e0da3c379521af1f85d7eef03a7860cfe2dcb3efd8dd32194f0981f0f0af7d5",
            "0ed2ebf596a4de07fa95b19774c506b178cac53df3292bfd3908f85c2433995a",
        ];
        assert_eq!(expect_proof, nmt_proof);
        assert!(proof.verify_with_leaves_data(&root,&[&[10]]).is_ok())
    }
    #[test]
    fn test_covert_1of16_celestia() {
        let root:[u8;32]= hex::decode("451f071b539a1b912ead47ff3ba769147903a3a23a1d466f93656f4933934ca8").unwrap().try_into().unwrap();
        let mut siblings: Vec<[u8; 32]> = vec![];
        let merkle_path = vec![
            "b413f47d13ee2fe6c845b2ee141af81de858df4ec549a58b7970bb96645bc8d2",
            "78850a5ab36238b076dd99fd258c70d523168704247988a94caa8c9ccd056b8d",
            "4301a067262bbb18b4919742326f6f6d706099f9c0e8b0f2db7b88f204b2cf09",
            "199fb6d33ec49c0d2ed928ed550d7efe5caa9b3e6298fb1e1f239d18fa6ca5cd",
        ];
        merkle_path.iter().for_each(|h| {
            siblings.push(hex::decode(h).unwrap().try_into().unwrap());
        });

        let proof = Proof::<TmSha2Hasher>::from_celestia_merkle_path(&siblings, 1, 16);
        let mut nmt_proof = Vec::new();
        proof.siblings
            .iter()
            .for_each(|h| nmt_proof.push(hex::encode(h)));
        let expect_proof = vec![
            "b413f47d13ee2fe6c845b2ee141af81de858df4ec549a58b7970bb96645bc8d2",
            "78850a5ab36238b076dd99fd258c70d523168704247988a94caa8c9ccd056b8d",
            "4301a067262bbb18b4919742326f6f6d706099f9c0e8b0f2db7b88f204b2cf09",
            "199fb6d33ec49c0d2ed928ed550d7efe5caa9b3e6298fb1e1f239d18fa6ca5cd",
        ];
        assert_eq!(expect_proof, nmt_proof);
        assert!(proof.verify_with_leaves_data(&root,&[&[2]]).is_ok())
    }

    #[test]
    fn test_covert_0of16_celestia() {
        let root:[u8;32]= hex::decode("451f071b539a1b912ead47ff3ba769147903a3a23a1d466f93656f4933934ca8").unwrap().try_into().unwrap();
        let mut siblings: Vec<[u8; 32]> = vec![];
        let merkle_path = vec![
            "fcf0a6c700dd13e274b6fba8deea8dd9b26e4eedde3495717cac8408c9c5177f",
            "78850a5ab36238b076dd99fd258c70d523168704247988a94caa8c9ccd056b8d",
            "4301a067262bbb18b4919742326f6f6d706099f9c0e8b0f2db7b88f204b2cf09",
            "199fb6d33ec49c0d2ed928ed550d7efe5caa9b3e6298fb1e1f239d18fa6ca5cd",
        ];
        merkle_path.iter().for_each(|h| {
            siblings.push(hex::decode(h).unwrap().try_into().unwrap());
        });

        let proof = Proof::<TmSha2Hasher>::from_celestia_merkle_path(&siblings, 0, 16);
        let mut nmt_proof = Vec::new();

        proof.siblings
            .iter()
            .for_each(|h| nmt_proof.push(hex::encode(h)));
        let expect_proof = vec![
            "fcf0a6c700dd13e274b6fba8deea8dd9b26e4eedde3495717cac8408c9c5177f",
            "78850a5ab36238b076dd99fd258c70d523168704247988a94caa8c9ccd056b8d",
            "4301a067262bbb18b4919742326f6f6d706099f9c0e8b0f2db7b88f204b2cf09",
            "199fb6d33ec49c0d2ed928ed550d7efe5caa9b3e6298fb1e1f239d18fa6ca5cd",
        ];
        assert_eq!(expect_proof, nmt_proof);
        assert!(proof.verify_with_leaves_data(&root,&[&[1]]).is_ok())
    }

    #[test]
    fn test_covert_2of16_celestia() {
        let root:[u8;32]= hex::decode("451f071b539a1b912ead47ff3ba769147903a3a23a1d466f93656f4933934ca8").unwrap().try_into().unwrap();
        let mut siblings: Vec<[u8; 32]> = vec![];
        let merkle_path = vec![
            "4f35212d12f9ad2036492c95f1fe79baf4ec7bd9bef3dffa7579f2293ff546a4",
            "6bcf0e2e93e0a18e22789aee965e6553f4fbe93f0acfc4a705d691c8311c4965",
            "4301a067262bbb18b4919742326f6f6d706099f9c0e8b0f2db7b88f204b2cf09",
            "199fb6d33ec49c0d2ed928ed550d7efe5caa9b3e6298fb1e1f239d18fa6ca5cd",
        ];
        merkle_path.iter().for_each(|h| {
            siblings.push(hex::decode(h).unwrap().try_into().unwrap());
        });

        let proof = Proof::<TmSha2Hasher>::from_celestia_merkle_path(&siblings, 2, 16);
        let mut nmt_proof = Vec::new();
        proof.siblings
            .iter()
            .for_each(|h| nmt_proof.push(hex::encode(h)));
        let expect_proof = vec![
            "6bcf0e2e93e0a18e22789aee965e6553f4fbe93f0acfc4a705d691c8311c4965",
            "4f35212d12f9ad2036492c95f1fe79baf4ec7bd9bef3dffa7579f2293ff546a4",
            "4301a067262bbb18b4919742326f6f6d706099f9c0e8b0f2db7b88f204b2cf09",
            "199fb6d33ec49c0d2ed928ed550d7efe5caa9b3e6298fb1e1f239d18fa6ca5cd",
        ];
        assert_eq!(expect_proof, nmt_proof);
        assert!(proof.verify_with_leaves_data(&root,&[&[3]]).is_ok())
    }

    #[test]
    fn test_covert_3of16_celestia() {
        let root:[u8;32]= hex::decode("451f071b539a1b912ead47ff3ba769147903a3a23a1d466f93656f4933934ca8").unwrap().try_into().unwrap();
        let mut siblings: Vec<[u8; 32]> = vec![];
        let merkle_path = vec![
            "583c7dfb7b3055d99465544032a571e10a134b1b6f769422bbb71fd7fa167a5d",
            "6bcf0e2e93e0a18e22789aee965e6553f4fbe93f0acfc4a705d691c8311c4965",
            "4301a067262bbb18b4919742326f6f6d706099f9c0e8b0f2db7b88f204b2cf09",
            "199fb6d33ec49c0d2ed928ed550d7efe5caa9b3e6298fb1e1f239d18fa6ca5cd",
        ];
        merkle_path.iter().for_each(|h| {
            siblings.push(hex::decode(h).unwrap().try_into().unwrap());
        });

        let proof = Proof::<TmSha2Hasher>::from_celestia_merkle_path(&siblings, 3, 16);
        let mut nmt_proof = Vec::new();
        proof.siblings
            .iter()
            .for_each(|h| nmt_proof.push(hex::encode(h)));
        let expect_proof = vec![
            "6bcf0e2e93e0a18e22789aee965e6553f4fbe93f0acfc4a705d691c8311c4965",
            "583c7dfb7b3055d99465544032a571e10a134b1b6f769422bbb71fd7fa167a5d",
            "4301a067262bbb18b4919742326f6f6d706099f9c0e8b0f2db7b88f204b2cf09",
            "199fb6d33ec49c0d2ed928ed550d7efe5caa9b3e6298fb1e1f239d18fa6ca5cd",
        ];
        assert_eq!(expect_proof, nmt_proof);
        assert!(proof.verify_with_leaves_data(&root,&[&[4]]).is_ok())
    }
}
