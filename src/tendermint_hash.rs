use sha2::{Digest, Sha256};

use crate::simple_merkle::tree::MerkleHash;

const LEAF_PREFIX: &[u8] = &[0];
const INNER_PREFIX: &[u8] = &[1];

fn leaf_hash(bytes: &[u8]) -> [u8; 32] {
    //hash([LEAF_PREFIX, bytes].concat().as_slice())
    let mut hasher = Sha256::new();
    hasher.update(LEAF_PREFIX);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn inner_hash(left: &[u8], right: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(INNER_PREFIX);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// A sha256 hasher, compatible with [Tendermint merkle hash](https://github.com/informalsystems/tendermint-rs/blob/979456c9f33463944f97f7ea3900640e59f7ea6d/tendermint/src/merkle.rs)
#[derive(Debug)]
pub struct TmSha2Hasher;

impl Default for TmSha2Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl TmSha2Hasher {
    /// Create a new instance of the hasher
    pub fn new() -> Self {
        TmSha2Hasher
    }
}

impl MerkleHash for TmSha2Hasher {
    type Output = [u8; 32];

    const EMPTY_ROOT: Self::Output = [
        227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174, 65,
        228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
    ];

    fn hash_leaf(&self, data: &[u8]) -> Self::Output {
        leaf_hash(data)
    }
    fn hash_nodes(&self, left: &Self::Output, right: &Self::Output) -> Self::Output {
        inner_hash(left, right)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemDb, MerkleTree};
    use hex;
    use tendermint::merkle::simple_hash_from_byte_vectors;

    #[test]
    fn test_tm_hash_matches_upstream() {
        let leaves: Vec<&[u8]> = vec![b"leaf_1", b"leaf_2", b"leaf_3", b"leaf_4"];
        let hasher = TmSha2Hasher {};
        let mut tree: MerkleTree<MemDb<[u8; 32]>, TmSha2Hasher> = MerkleTree::with_hasher(hasher);
        leaves.iter().for_each(|leaf| {
            tree.push_raw_leaf(leaf);
        });
        let hash_from_byte_slices = simple_hash_from_byte_vectors::<Sha256>(leaves.as_slice());
        assert_eq!(tree.root().as_ref(), &hash_from_byte_slices);
    }

    // ---------------------------------------------------------
    // These test copy from solidity implementation
    // https://github.com/celestiaorg/blobstream-contracts/blob/dc02821/src/lib/tree/binary/test/TreeHasher.t.sol
    // ---------------------------------------------------------

    #[test]
    fn test_leaf_digest_empty() {
        let hasher = TmSha2Hasher {};
        let expected: [u8; 32] =
            hex::decode("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d")
                .unwrap()
                .try_into()
                .unwrap();
        let digest = hasher.hash_leaf(&vec![]);
        assert_eq!(digest, expected);
    }

    #[test]
    fn test_leaf_digest_some() {
        let hasher = TmSha2Hasher {};
        let expected: [u8; 32] =
            hex::decode("48c90c8ae24688d6bef5d48a30c2cc8b6754335a8db21793cc0a8e3bed321729")
                .unwrap()
                .try_into()
                .unwrap();
        let digest = hasher.hash_leaf(hex::decode("deadbeef").unwrap().as_slice());
        assert_eq!(digest, expected);
    }

    #[test]
    fn test_node_digest_empty_children() {
        let hasher = TmSha2Hasher {};
        let expected: [u8; 32] =
            hex::decode("fe43d66afa4a9a5c4f9c9da89f4ffb52635c8f342e7ffb731d68e36c5982072a")
                .unwrap()
                .try_into()
                .unwrap();
        let digest = hasher.hash_nodes(
            &hex::decode("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d")
                .unwrap()
                .try_into()
                .unwrap(),
            &hex::decode("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d")
                .unwrap()
                .try_into()
                .unwrap(),
        );
        assert_eq!(digest, expected);
    }

    #[test]
    fn test_node_digest_some_children() {
        let hasher = TmSha2Hasher {};
        let expected: [u8; 32] =
            hex::decode("62343bba7c4d6259f0d4863cdf476f1c0ac1b9fbe9244723a9b8b5c8aae72c38")
                .unwrap()
                .try_into()
                .unwrap();
        let digest = hasher.hash_nodes(
            &hex::decode("db55da3fc3098e9c42311c6013304ff36b19ef73d12ea932054b5ad51df4f49d")
                .unwrap()
                .try_into()
                .unwrap(),
            &hex::decode("c75cb66ae28d8ebc6eded002c28a8ba0d06d3a78c6b5cbf9b2ade051f0775ac4")
                .unwrap()
                .try_into()
                .unwrap(),
        );
        assert_eq!(digest, expected);
    }
}
