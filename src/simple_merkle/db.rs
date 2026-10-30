use crate::{maybestd::vec::Vec, NamespaceId, NamespaceMerkleHasher, NamespacedHash};

use super::tree::MerkleHash;

/// The raw data of the leaf, together with its hash under some [`MerkleHash`]er
#[derive(Clone)]
pub struct LeafWithHash<H: MerkleHash> {
    data: Vec<u8>,
    hash: H::Output,
}

impl<H: MerkleHash + Default> LeafWithHash<H> {
    /// Construct a [`LeafWithHash`] by hashing the provided data
    pub fn new(data: Vec<u8>) -> Self {
        let hash = H::default().hash_leaf(&data);
        Self { data, hash }
    }
}

impl<H: MerkleHash> LeafWithHash<H> {
    /// Construct a [`LeafWithHash`] by hashing the provided data
    pub fn with_hasher(data: Vec<u8>, hasher: &H) -> Self {
        let hash = hasher.hash_leaf(&data);
        Self { data, hash }
    }

    /// Returns the raw data from the leaf
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns the hash of the leaf data
    pub fn hash(&self) -> &H::Output {
        &self.hash
    }
}

impl<
        M: NamespaceMerkleHasher<NS_ID_SIZE, Output = NamespacedHash<NS_ID_SIZE>>,
        const NS_ID_SIZE: usize,
    > LeafWithHash<M>
{
    /// Create a new leaf with the provided namespace. Only available if the hasher supports namespacing.
    pub fn new_with_namespace(
        data: Vec<u8>,
        namespace: NamespaceId<NS_ID_SIZE>,
        ignore_max_ns: bool,
    ) -> Self {
        Self::with_namespace_and_hasher(data, namespace, &M::with_ignore_max_ns(ignore_max_ns))
    }

    /// Create a new leaf with the provided namespace, hashed by the provided hasher.
    pub fn with_namespace_and_hasher(
        data: Vec<u8>,
        namespace: NamespaceId<NS_ID_SIZE>,
        hasher: &M,
    ) -> Self {
        let hash = hasher.hash_leaf_with_namespace(&data, namespace);
        Self { data, hash }
    }
}
