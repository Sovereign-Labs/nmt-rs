use sha2::{Digest, Sha256};

use crate::simple_merkle::tree::MerkleHash;
pub const HASH_LEN: usize = 32;
pub const NAMESPACE_ID_LEN: usize = 8;
pub const NAMESPACED_HASH_LEN: usize = HASH_LEN + 2 * NAMESPACE_ID_LEN;
pub type Hasher = Sha256;

pub const LEAF_DOMAIN_SEPARATOR: [u8; 1] = [0u8];
pub const INTERNAL_NODE_DOMAIN_SEPARATOR: [u8; 1] = [1u8];
pub const MAX_NS: NamespaceId = NamespaceId([0xff; NAMESPACE_ID_LEN]);

#[derive(Debug)]
pub struct NamespacedSha2Hasher {
    ignore_max_ns: bool,
}

impl NamespaceMerkleHasher for NamespacedSha2Hasher {
    fn with_ignore_max_ns(ignore_max_ns: bool) -> Self {
        Self { ignore_max_ns }
    }

    fn ignores_max_ns(&self) -> bool {
        self.ignore_max_ns
    }
}

impl Default for NamespacedSha2Hasher {
    fn default() -> Self {
        Self {
            ignore_max_ns: true,
        }
    }
}

pub trait NamespaceMerkleHasher: MerkleHash {
    fn with_ignore_max_ns(ignore_max_ns: bool) -> Self;
    fn ignores_max_ns(&self) -> bool;
}

impl MerkleHash for NamespacedSha2Hasher {
    type Output = NamespacedHash;

    const EMPTY_ROOT: Self::Output = NamespacedHash([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 227, 176, 196, 66, 152, 252, 28, 20, 154,
        251, 244, 200, 153, 111, 185, 36, 39, 174, 65, 228, 100, 155, 147, 76, 164, 149, 153, 27,
        120, 82, 184, 85,
    ]);

    fn hash_leaf(&self, data: &[u8]) -> Self::Output {
        let mut namespace_bytes = [0u8; NAMESPACE_ID_LEN];
        namespace_bytes.copy_from_slice(&data[..8]);
        let namespace = NamespaceId(namespace_bytes);

        let mut output = NamespacedHash::with_min_and_max_ns(namespace, namespace);
        let mut hasher = Hasher::new_with_prefix(&LEAF_DOMAIN_SEPARATOR);
        hasher.update(data.as_ref());
        output.set_hash(hasher.finalize().as_ref());
        output
    }

    fn hash_nodes(&self, left: &Self::Output, right: &Self::Output) -> Self::Output {
        if left.max_namespace() > right.min_namespace() {
            panic!("Invalid nodes: left max namespace must be <= right min namespace")
        }
        let mut hasher = Hasher::new_with_prefix(INTERNAL_NODE_DOMAIN_SEPARATOR);

        let min_ns = std::cmp::min(left.min_namespace(), right.min_namespace());
        let max_ns = if self.ignore_max_ns && left.min_namespace() == MAX_NS {
            MAX_NS
        } else if self.ignore_max_ns && right.min_namespace() == MAX_NS {
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
}

pub const EMPTY_ROOT: NamespacedHash = NamespacedHash([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 227, 176, 196, 66, 152, 252, 28, 20, 154, 251,
    244, 200, 153, 111, 185, 36, 39, 174, 65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82,
    184, 85,
]);

#[derive(Debug, PartialEq, PartialOrd, Eq, Ord, Copy, Clone, Hash)]
pub struct NamespaceId(pub [u8; NAMESPACE_ID_LEN]);

impl NamespaceId {
    pub fn is_reserved(&self) -> bool {
        self.0 <= [0, 0, 0, 0, 0, 0, 0, 255]
    }
}

impl AsRef<[u8]> for NamespaceId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct NamespacedHash(pub [u8; NAMESPACED_HASH_LEN]);

impl Default for NamespacedHash {
    fn default() -> Self {
        Self([0u8; NAMESPACED_HASH_LEN])
    }
}

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

    pub fn empty() -> Self {
        EMPTY_ROOT.clone()
    }

    pub fn contains(&self, namespace: NamespaceId) -> bool {
        self.min_namespace() <= namespace
            && self.max_namespace() >= namespace
            && !self.is_empty_root()
    }

    pub fn is_empty_root(&self) -> bool {
        self == &EMPTY_ROOT
    }

    pub fn hash_leaf(raw_data: impl AsRef<[u8]>, namespace: NamespaceId) -> Self {
        let mut output = NamespacedHash::with_min_and_max_ns(namespace, namespace);
        let mut hasher = Hasher::new_with_prefix(&LEAF_DOMAIN_SEPARATOR);
        hasher.update(namespace.as_ref());
        hasher.update(raw_data.as_ref());
        output.set_hash(hasher.finalize().as_ref());
        output
    }
}

impl AsRef<[u8]> for NamespacedHash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub struct InvalidNamespace;

impl std::fmt::Display for InvalidNamespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InvalidNamespace")
    }
}
impl std::error::Error for InvalidNamespace {}

impl TryFrom<&[u8]> for NamespaceId {
    type Error = InvalidNamespace;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != NAMESPACE_ID_LEN {
            return Err(InvalidNamespace);
        }
        let mut out = [0u8; NAMESPACE_ID_LEN];
        out.copy_from_slice(value);
        Ok(Self(out))
    }
}
