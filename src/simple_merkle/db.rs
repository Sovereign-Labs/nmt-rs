use crate::{
    maybestd::{hash::Hash, vec::Vec},
    NamespaceId, NamespaceMerkleHasher, NamespacedHash,
};

use super::tree::MerkleHash;

#[cfg(not(feature = "std"))]
trait HashType: Eq + Hash + crate::maybestd::cmp::Ord {}

#[cfg(not(feature = "std"))]
impl<H: Eq + Hash + Ord> HashType for H {}

#[cfg(feature = "std")]
trait HashType: Eq + Hash {}

#[cfg(feature = "std")]
impl<H: Eq + Hash> HashType for H {}

/// Maintains a mapping from hash to preimage in memory. Backed by a [`crate::maybestd::hash_or_btree_map::Map<H, Node<H>>`]
#[derive(Default)]
pub struct MemDb<H>(crate::maybestd::hash_or_btree_map::Map<H, Node<H>>);

impl<H: HashType> PreimageReader<H> for MemDb<H> {
    fn get(&self, image: &H) -> Option<&Node<H>> {
        self.0.get(image)
    }
}
impl<H: HashType> PreimageWriter<H> for MemDb<H> {
    fn put(&mut self, image: H, preimage: Node<H>) {
        self.0.insert(image, preimage);
    }
}

impl<H: Default + HashType> PreimageDb<H> for MemDb<H> {}

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
        let hasher = M::with_ignore_max_ns(ignore_max_ns);
        let hash = hasher.hash_leaf_with_namespace(&data, namespace);
        Self { data, hash }
    }
}

/// A node of a merkle tree
#[derive(PartialEq, Clone, Debug)]
pub enum Node<H> {
    /// A leaf node contains raw data
    Leaf(Vec<u8>),
    /// An inner node is the concatenation of two child nodes
    Inner(H, H),
}

/// The reader trait for a data store that maps hashes to preimages
pub trait PreimageReader<H> {
    /// Get the preimage of a given hash
    fn get(&self, image: &H) -> Option<&Node<H>>;
}

/// The writer trait for a data store that maps hashes to preimages
pub trait PreimageWriter<H> {
    /// Store the preimage of a given hash
    fn put(&mut self, image: H, preimage: Node<H>);
}

/// A trait representing read and write access to data store that maps hashes to their preimages
pub trait PreimageDb<H>: PreimageReader<H> + PreimageWriter<H> + Default {}

/// A PreimageDB that drops all stored items. Should only be used in trees that
/// do not create proofs (i.e. trees used only for proof verification)
#[derive(Default)]
pub struct NoopDb;

impl<H: Eq + Hash> PreimageReader<H> for NoopDb {
    fn get(&self, _image: &H) -> Option<&Node<H>> {
        None
    }
}
impl<H: Eq + Hash> PreimageWriter<H> for NoopDb {
    fn put(&mut self, _image: H, _preimage: Node<H>) {}
}

impl<H: Default + Eq + Hash> PreimageDb<H> for NoopDb {}

#[cfg(test)]
mod test {
    #[test]
    fn test_mem_db() {
        use super::*;
        let mut db = MemDb::<u32>::default();
        let leaf = Node::Leaf(vec![1, 2, 3]);
        db.put(1, leaf.clone());
        assert_eq!(db.get(&1), Some(&leaf));

        let node = Node::Inner(1, 2);
        db.put(2, node.clone());
        assert_eq!(db.get(&2), Some(&node));
    }
}
