use crate::maybestd::{hash::Hash, vec::Vec};

#[cfg(not(feature = "std"))]
trait HashType: Eq + Hash + crate::maybestd::cmp::Ord {}

#[cfg(not(feature = "std"))]
impl<H: Eq + Hash + Ord> HashType for H {}

#[cfg(feature = "std")]
trait HashType: Eq + Hash {}

#[cfg(feature = "std")]
impl<H: Eq + Hash> HashType for H {}

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

#[derive(Clone)]
pub struct LeafWithHash<H> {
    pub data: Vec<u8>,
    pub hash: H,
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
