use std::collections::HashMap;

use crate::namespaced_hash::NamespacedHash;

#[derive(Default)]
pub struct MemDb(HashMap<NamespacedHash, Node>);

impl PreimageReader for MemDb {
    fn get(&self, image: &NamespacedHash) -> Option<&Node> {
        self.0.get(image)
    }
}
impl PreimageWriter for MemDb {
    fn put(&mut self, image: NamespacedHash, preimage: Node) {
        self.0.insert(image, preimage);
    }
}

impl PreimageDb for MemDb {}

#[derive(Clone)]
pub struct LeafWithHash {
    pub data: Vec<u8>,
    pub hash: NamespacedHash,
}

#[derive(PartialEq, Clone, Debug)]
pub enum Node {
    Leaf(Vec<u8>),
    Inner(NamespacedHash, NamespacedHash),
}

pub trait PreimageReader {
    fn get(&self, image: &NamespacedHash) -> Option<&Node>;
}

pub trait PreimageWriter {
    fn put(&mut self, image: NamespacedHash, preimage: Node);
}

pub trait PreimageDb: PreimageReader + PreimageWriter + Default {}
