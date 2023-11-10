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

/// A
#[derive(Clone)]
pub struct LeafWithHash<H: MerkleHash> {
    data: Vec<u8>,
    hash: H::Output,
}

impl<H: MerkleHash> LeafWithHash<H> {
    pub fn new(data: Vec<u8>) -> Self {
        let hash = H::default().hash_leaf(&data);
        Self { data, hash }
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

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
    pub fn new_with_namespace(data: Vec<u8>, namespace: NamespaceId<NS_ID_SIZE>) -> Self {
        let hash = M::hash_leaf_with_namespace(&data, namespace);
        Self { data, hash }
    }
}

#[derive(PartialEq, Clone, Debug)]
pub enum Node<H> {
    Leaf(Vec<u8>),
    Inner(H, H),
}

pub trait PreimageReader<H> {
    fn get(&self, image: &H) -> Option<&Node<H>>;
}

pub trait PreimageWriter<H> {
    fn put(&mut self, image: H, preimage: Node<H>);
}

pub trait PreimageDb<H>: PreimageReader<H> + PreimageWriter<H> + Default {}

/// A PreimageDB that drops all stored items. Should only be used in trees that
/// do not create proofs (i.e. trees used only for proof  verification)
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
