#![feature(array_chunks)]
use std::{cell::RefCell, collections::HashMap, ops::Range};

use sha2::{Digest, Sha256};

const HASH_LEN: usize = 32;
const NAMESPACE_ID_LEN: usize = 8;
const NAMESPACED_HASH_LEN: usize = HASH_LEN + 2 * NAMESPACE_ID_LEN;
pub type Hasher = Sha256;

pub const LEAF_DOMAIN_SEPARATOR: [u8; 1] = [0u8];
pub const INTERNAL_NODE_DOMAIN_SEPARATOR: [u8; 1] = [1u8];

#[derive(Debug, PartialEq, PartialOrd, Eq, Ord, Copy, Clone)]
pub struct NamespaceId(pub [u8; NAMESPACE_ID_LEN]);

impl AsRef<[u8]> for NamespaceId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct NamespacedHash(pub [u8; NAMESPACED_HASH_LEN]);

impl NamespacedHash {
    pub fn with_min_and_max_ns(min_namespace: NamespaceId, max_namespace: NamespaceId) -> Self {
        let mut out = Self([0u8; NAMESPACED_HASH_LEN]);
        out.0[0..NAMESPACE_ID_LEN].copy_from_slice(min_namespace.as_ref());
        out.0[NAMESPACE_ID_LEN..2 * NAMESPACE_ID_LEN].copy_from_slice(max_namespace.as_ref());
        out
    }
    pub fn min_namespace(&self) -> NamespaceId {
        let mut out = [0u8; NAMESPACE_ID_LEN];
        out.copy_from_slice(&self.0[..NAMESPACE_ID_LEN]);
        NamespaceId(out)
    }

    pub fn max_namespace(&self) -> NamespaceId {
        let mut out = [0u8; NAMESPACE_ID_LEN];
        out.copy_from_slice(&self.0[NAMESPACE_ID_LEN..2 * NAMESPACE_ID_LEN]);
        NamespaceId(out)
    }

    fn set_hash(&mut self, hash: &[u8]) {
        self.0[2 * NAMESPACE_ID_LEN..].copy_from_slice(hash)
    }

    pub fn hash_leaf<'a>(raw_data: &'a [u8], namespace: NamespaceId) -> Self {
        let mut output = NamespacedHash::with_min_and_max_ns(namespace, namespace);
        let mut hasher = Hasher::new_with_prefix(&LEAF_DOMAIN_SEPARATOR);
        hasher.update(namespace.as_ref());
        hasher.update(raw_data);
        output.set_hash(hasher.finalize().as_ref());
        output
    }

    pub fn empty() -> Self {
        let mut out = Self([0u8; NAMESPACED_HASH_LEN]);
        out.set_hash(Hasher::new().finalize().as_ref());
        out
    }
}

impl AsRef<[u8]> for NamespacedHash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

pub struct LeafWithHash {
    data: Vec<u8>,
    pub hash: NamespacedHash,
}

pub struct NamespaceMerkleTree {
    leaves: Vec<LeafWithHash>,
    ignore_max_ns: bool,
    precomputed_max_ns: NamespaceId,
    min_namespace: NamespaceId,
    max_namespace: NamespaceId,
    namespace_ranges: HashMap<NamespaceId, Range<usize>>,
    root: RefCell<Option<NamespacedHash>>,
    visitor: Box<dyn Fn(&NamespacedHash)>,
}

impl NamespaceMerkleTree {
    pub fn new() -> Self {
        Self {
            leaves: vec![],
            ignore_max_ns: true,
            precomputed_max_ns: NamespaceId([0xff; NAMESPACE_ID_LEN]),
            // Initialize the min namespace to be the maximum possible, so that the check
            // x <= tree.min_namespace is always true for the empty tree
            min_namespace: NamespaceId([0xff; NAMESPACE_ID_LEN]),
            // Similarly set the max namespace to be the maximum possible, so that the check
            // x >= tree.max_namespace is always true for the empty tree
            max_namespace: NamespaceId([0x00; NAMESPACE_ID_LEN]),
            namespace_ranges: Default::default(),
            root: RefCell::new(Some(NamespacedHash::empty())),
            visitor: Box::new(|_| {}),
        }
    }

    fn update_min_max_ids(&mut self, namespace: NamespaceId) {
        // Note: these two conditions are not mutually exclusive!
        // We initialize min_namespace to be greater than max_namespace
        if namespace < self.min_namespace {
            self.min_namespace = namespace
        }
        if namespace > self.max_namespace {
            self.max_namespace = namespace
        }
    }

    pub fn hash_nodes(&self, left: NamespacedHash, right: NamespacedHash) -> NamespacedHash {
        let mut hasher = Hasher::new_with_prefix(INTERNAL_NODE_DOMAIN_SEPARATOR);

        let min_ns = std::cmp::min(left.min_namespace(), right.min_namespace());
        let max_ns = if self.ignore_max_ns && left.min_namespace() == self.precomputed_max_ns {
            self.precomputed_max_ns
        } else if self.ignore_max_ns && right.min_namespace() == self.precomputed_max_ns {
            left.max_namespace()
        } else {
            std::cmp::max(left.max_namespace(), right.max_namespace())
        };

        let mut output = NamespacedHash::with_min_and_max_ns(min_ns, max_ns);

        hasher.update(left);
        hasher.update(right);

        output.set_hash(hasher.finalize().as_ref());
        output
    }

    pub fn root(&self) -> NamespacedHash {
        self.root
            .borrow_mut()
            .get_or_insert_with(|| self.compute_root(&self.leaves[..]))
            .clone()
    }

    pub fn compute_root(&self, leaves: &[LeafWithHash]) -> NamespacedHash {
        match leaves.len() {
            0 => {
                let root = NamespacedHash::empty();
                (self.visitor)(&root);
                root
            }
            1 => {
                let root = leaves[0].hash.clone();
                (self.visitor)(&root);
                root
            }
            _ => {
                let split_point = next_smaller_po2(leaves.len());
                let left = self.compute_root(&leaves[..split_point]);
                let right = self.compute_root(&leaves[split_point..]);
                let root = self.hash_nodes(left, right);
                (self.visitor)(&root);
                root
            }
        }
    }

    fn build_range_proof(&self, leaves: &[LeafWithHash]) -> Vec<NamespacedHash> {
        if leaves.len() == 1 {
            let hash = leaves[0].hash.clone();
        }
        todo!()
    }
}

/// Calculates the largest power of two which is strictly less than the argument
fn next_smaller_po2(int: usize) -> usize {
    // Calculate the first power of two which is greater than or equal to the argument, then divide by two.
    int.next_power_of_two() >> 1
}
