use sha2::{Sha256, Digest};

use crate::simple_merkle::tree::MerkleHash;

fn hash(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let result: [u8; 32] = hasher.finalize().into();
    result
}

const LEAF_PREFIX: &[u8] = &[0];
const INNER_PREFIX: &[u8] = &[1];

fn leaf_hash(bytes: &[u8]) -> [u8; 32] {
    hash([LEAF_PREFIX, bytes].concat().as_slice())
}

fn inner_hash(left: &[u8], right: &[u8]) -> [u8; 32] {
    hash([INNER_PREFIX, left, right].concat().as_slice())
}

/// A sha256 hasher, compatible with [Tendermint merkle hash](https://github.com/informalsystems/tendermint-rs/blob/979456c9f33463944f97f7ea3900640e59f7ea6d/tendermint/src/merkle.rs)
pub struct TmSha2Hasher;

impl TmSha2Hasher {
    /// Create a new instance of the hasher
    pub fn new() -> Self {
        TmSha2Hasher
    }
}

impl MerkleHash for TmSha2Hasher {
    type Output = [u8; 32];

    const EMPTY_ROOT : Self::Output = [227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174, 65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85];

    fn hash_leaf(&self, data: &[u8]) -> Self::Output {
        leaf_hash(data)
    }
    fn hash_nodes(&self, left: &Self::Output, right: &Self::Output) -> Self::Output {
        inner_hash(left, right)
    }
}