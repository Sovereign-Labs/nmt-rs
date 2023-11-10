use crate::maybestd::{cmp, fmt, marker::PhantomData, vec::Vec};
use sha2::{Digest, Sha256};

use crate::simple_merkle::tree::MerkleHash;
pub const HASH_LEN: usize = 32;
pub type Hasher = Sha256;

pub const LEAF_DOMAIN_SEPARATOR: [u8; 1] = [0u8];
pub const INTERNAL_NODE_DOMAIN_SEPARATOR: [u8; 1] = [1u8];

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NamespacedSha2Hasher<const NS_ID_SIZE: usize> {
    ignore_max_ns: bool,
    _data: PhantomData<[u8; NS_ID_SIZE]>,
}

impl<const NS_ID_SIZE: usize> NamespaceMerkleHasher<NS_ID_SIZE>
    for NamespacedSha2Hasher<NS_ID_SIZE>
{
    fn with_ignore_max_ns(ignore_max_ns: bool) -> Self {
        Self {
            ignore_max_ns,
            _data: PhantomData,
        }
    }

    fn ignores_max_ns(&self) -> bool {
        self.ignore_max_ns
    }

    fn hash_leaf_with_namespace(
        data: &[u8],
        namespace: NamespaceId<NS_ID_SIZE>,
    ) -> <Self as MerkleHash>::Output {
        NamespacedHash::hash_leaf(data, namespace)
    }
}

impl<const NS_ID_SIZE: usize> Default for NamespacedSha2Hasher<NS_ID_SIZE> {
    fn default() -> Self {
        Self {
            ignore_max_ns: true,
            _data: PhantomData,
        }
    }
}

pub trait NamespaceMerkleHasher<const NS_ID_SIZE: usize>: MerkleHash {
    fn with_ignore_max_ns(ignore_max_ns: bool) -> Self;
    fn ignores_max_ns(&self) -> bool;
    fn hash_leaf_with_namespace(
        data: &[u8],
        namespace: NamespaceId<NS_ID_SIZE>,
    ) -> <Self as MerkleHash>::Output;
}

impl<const NS_ID_SIZE: usize> MerkleHash for NamespacedSha2Hasher<NS_ID_SIZE> {
    type Output = NamespacedHash<NS_ID_SIZE>;

    const EMPTY_ROOT: Self::Output = NamespacedHash::EMPTY_ROOT;

    fn hash_leaf(&self, data: &[u8]) -> Self::Output {
        let namespace_bytes = data[..NS_ID_SIZE].try_into().expect("Leaf of invalid size");
        let namespace = NamespaceId(namespace_bytes);

        let mut output = NamespacedHash::with_min_and_max_ns(namespace, namespace);
        let mut hasher = Hasher::new_with_prefix(LEAF_DOMAIN_SEPARATOR);
        hasher.update(data.as_ref());
        output.set_hash(hasher.finalize().as_ref());
        output
    }

    fn hash_nodes(&self, left: &Self::Output, right: &Self::Output) -> Self::Output {
        if left.max_namespace() > right.min_namespace() {
            panic!("Invalid nodes: left max namespace must be <= right min namespace")
        }
        let mut hasher = Hasher::new_with_prefix(INTERNAL_NODE_DOMAIN_SEPARATOR);
        let max_nsid = NamespaceId::<NS_ID_SIZE>::max_id();

        let min_ns = cmp::min(left.min_namespace(), right.min_namespace());
        let max_ns = if self.ignore_max_ns && left.min_namespace() == max_nsid {
            max_nsid
        } else if self.ignore_max_ns && right.min_namespace() == max_nsid {
            left.max_namespace()
        } else {
            cmp::max(left.max_namespace(), right.max_namespace())
        };

        let mut output = NamespacedHash::with_min_and_max_ns(min_ns, max_ns);

        hasher.update(&left.iter().collect::<Vec<_>>());
        hasher.update(&right.iter().collect::<Vec<_>>());

        output.set_hash(hasher.finalize().as_ref());
        output
    }
}

#[derive(Debug, PartialEq, PartialOrd, Eq, Ord, Copy, Clone, Hash)]
#[cfg_attr(any(test, feature = "borsh"), derive(borsh::BorshSerialize))]
pub struct NamespaceId<const NS_ID_SIZE: usize>(pub [u8; NS_ID_SIZE]);

impl<const NS_ID_SIZE: usize> Default for NamespaceId<NS_ID_SIZE> {
    fn default() -> Self {
        Self([0; NS_ID_SIZE])
    }
}

impl<const NS_ID_SIZE: usize> NamespaceId<NS_ID_SIZE> {
    pub const MAX_ID: NamespaceId<NS_ID_SIZE> = NamespaceId([0xff; NS_ID_SIZE]);
    pub const MAX_RESERVED_ID: NamespaceId<NS_ID_SIZE> = {
        let mut max_reserved = [0; NS_ID_SIZE];
        max_reserved[NS_ID_SIZE - 1] = 255;
        Self(max_reserved)
    };

    pub const fn max_id() -> Self {
        Self::MAX_ID
    }

    pub fn is_reserved(&self) -> bool {
        self <= &Self::MAX_RESERVED_ID
    }
}

impl<const NS_ID_SIZE: usize> AsRef<[u8]> for NamespaceId<NS_ID_SIZE> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub struct InvalidNamespace;

impl fmt::Display for InvalidNamespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InvalidNamespace")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidNamespace {}

impl<const NS_ID_SIZE: usize> TryFrom<&[u8]> for NamespaceId<NS_ID_SIZE> {
    type Error = InvalidNamespace;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != NS_ID_SIZE {
            return Err(InvalidNamespace);
        }
        Ok(Self(value.try_into().unwrap()))
    }
}

#[derive(Debug, PartialEq, Clone, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(any(test, feature = "borsh"), derive(borsh::BorshSerialize))]
pub struct NamespacedHash<const NS_ID_SIZE: usize> {
    min_ns: NamespaceId<NS_ID_SIZE>,
    max_ns: NamespaceId<NS_ID_SIZE>,
    hash: [u8; HASH_LEN],
}

#[cfg(any(test, feature = "borsh"))]
impl<const NS_ID_SIZE: usize> borsh::BorshDeserialize for NamespacedHash<NS_ID_SIZE> {
    fn deserialize_reader<R: borsh::maybestd::io::Read>(
        reader: &mut R,
    ) -> borsh::maybestd::io::Result<Self> {
        let mut min_ns = NamespaceId([0u8; NS_ID_SIZE]);
        reader.read_exact(&mut min_ns.0)?;

        let mut max_ns = NamespaceId([0u8; NS_ID_SIZE]);
        reader.read_exact(&mut max_ns.0)?;

        let mut hash = [0u8; HASH_LEN];
        reader.read_exact(&mut hash)?;

        Ok(NamespacedHash {
            min_ns,
            max_ns,
            hash,
        })
    }
}

#[cfg(feature = "serde")]
impl<const NS_ID_SIZE: usize> serde::Serialize for NamespacedHash<NS_ID_SIZE> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeTuple;
        let mut seq = serializer.serialize_tuple(NamespacedHash::<NS_ID_SIZE>::size())?;
        for byte in self.iter() {
            seq.serialize_element(&byte)?;
        }
        seq.end()
    }
}

#[cfg(feature = "serde")]
impl<'de, const NS_ID_SIZE: usize> serde::Deserialize<'de> for NamespacedHash<NS_ID_SIZE> {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as serde::Deserializer<'de>>::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ArrayVisitor<T, const NS_ID_SIZE: usize> {
            element: PhantomData<[T; NS_ID_SIZE]>,
        }

        impl<'de, T, const NS_ID_SIZE: usize> serde::de::Visitor<'de> for ArrayVisitor<T, NS_ID_SIZE>
        where
            T: Default + Copy + serde::Deserialize<'de>,
        {
            type Value = NamespacedHash<NS_ID_SIZE>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(&crate::maybestd::format!(
                    "an array of length {}",
                    NamespacedHash::<NS_ID_SIZE>::size()
                ))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let seq: Vec<u8> = (0..NamespacedHash::<NS_ID_SIZE>::size())
                    .map(|i| {
                        seq.next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(i, &self))
                    })
                    .collect::<Result<_, _>>()?;
                let ns_hash = seq
                    .as_slice()
                    .try_into()
                    .map_err(|e: InvalidNamespacedHash| {
                        serde::de::Error::custom(crate::maybestd::string::ToString::to_string(&e))
                    })?;
                Ok(ns_hash)
            }
        }

        let visitor = ArrayVisitor {
            element: PhantomData::<[u8; NS_ID_SIZE]>,
        };

        deserializer.deserialize_tuple(NamespacedHash::<NS_ID_SIZE>::size(), visitor)
    }
}

impl<const NS_ID_SIZE: usize> Default for NamespacedHash<NS_ID_SIZE> {
    fn default() -> Self {
        Self {
            min_ns: NamespaceId::default(),
            max_ns: NamespaceId::default(),
            hash: [0u8; HASH_LEN],
        }
    }
}

impl<const NS_ID_SIZE: usize> NamespacedHash<NS_ID_SIZE> {
    pub const EMPTY_ROOT: NamespacedHash<NS_ID_SIZE> = Self {
        min_ns: NamespaceId([0; NS_ID_SIZE]),
        max_ns: NamespaceId([0; NS_ID_SIZE]),
        hash: [
            227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174,
            65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
        ],
    };

    pub const fn size() -> usize {
        2 * NS_ID_SIZE + HASH_LEN
    }

    pub const fn new(
        min_ns: NamespaceId<NS_ID_SIZE>,
        max_ns: NamespaceId<NS_ID_SIZE>,
        hash: [u8; HASH_LEN],
    ) -> Self {
        Self {
            min_ns,
            max_ns,
            hash,
        }
    }

    pub fn with_min_and_max_ns(
        min_ns: NamespaceId<NS_ID_SIZE>,
        max_ns: NamespaceId<NS_ID_SIZE>,
    ) -> Self {
        Self {
            min_ns,
            max_ns,
            ..Default::default()
        }
    }

    pub fn min_namespace(&self) -> NamespaceId<NS_ID_SIZE> {
        self.min_ns
    }

    pub fn max_namespace(&self) -> NamespaceId<NS_ID_SIZE> {
        self.max_ns
    }

    pub fn hash(&self) -> [u8; HASH_LEN] {
        self.hash
    }

    fn set_hash(&mut self, new_hash: &[u8]) {
        self.hash.copy_from_slice(new_hash)
    }

    pub fn contains(&self, namespace: NamespaceId<NS_ID_SIZE>) -> bool {
        self.min_namespace() <= namespace
            && self.max_namespace() >= namespace
            && !self.is_empty_root()
    }

    pub fn is_empty_root(&self) -> bool {
        self == &Self::EMPTY_ROOT
    }

    pub fn hash_leaf(raw_data: impl AsRef<[u8]>, namespace: NamespaceId<NS_ID_SIZE>) -> Self {
        let mut output = NamespacedHash::with_min_and_max_ns(namespace, namespace);
        let mut hasher = Hasher::new_with_prefix(LEAF_DOMAIN_SEPARATOR);
        hasher.update(namespace.as_ref());
        hasher.update(raw_data.as_ref());
        output.set_hash(hasher.finalize().as_ref());
        output
    }

    pub fn iter(&self) -> impl Iterator<Item = u8> {
        self.min_ns
            .0
            .into_iter()
            .chain(self.max_ns.0)
            .chain(self.hash)
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub struct InvalidNamespacedHash;

impl fmt::Display for InvalidNamespacedHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InvalidNamespacedHash")
    }
}
#[cfg(feature = "std")]
impl std::error::Error for InvalidNamespacedHash {}

impl<const NS_ID_SIZE: usize> TryFrom<&[u8]> for NamespacedHash<NS_ID_SIZE> {
    type Error = InvalidNamespacedHash;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != NamespacedHash::<NS_ID_SIZE>::size() {
            return Err(InvalidNamespacedHash);
        }
        Ok(Self {
            min_ns: value[..NS_ID_SIZE].try_into().unwrap(),
            max_ns: value[NS_ID_SIZE..2 * NS_ID_SIZE].try_into().unwrap(),
            hash: value[2 * NS_ID_SIZE..].try_into().unwrap(),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::NamespacedHash;
    use borsh::de::BorshDeserialize;
    use borsh::ser::BorshSerialize;

    #[test]
    fn test_namespaced_hash_borsh() {
        let hash = NamespacedHash::<8>::try_from([8u8; 48].as_ref()).unwrap();

        let serialized = hash
            .try_to_vec()
            .expect("Serialization to vec must succeed");

        let got =
            NamespacedHash::deserialize(&mut &serialized[..]).expect("serialized hash is correct");

        assert_eq!(got, hash);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_namespaced_hash_serde_json() {
        let hash = NamespacedHash::<8>::try_from([8u8; 48].as_ref()).unwrap();

        let serialized = serde_json::to_vec(&hash).expect("Serialization to vec must succeed");

        let got: NamespacedHash<8> =
            serde_json::from_slice(&serialized[..]).expect("serialized hash is correct");

        assert_eq!(got, hash);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_namespaced_hash_serde_postcard() {
        use crate::maybestd::vec::Vec;

        let hash = NamespacedHash::<8>::try_from([8u8; 48].as_ref()).unwrap();

        let serialized: Vec<u8> =
            postcard::to_allocvec(&hash).expect("Serialization to vec must succeed");
        let got: NamespacedHash<8> =
            postcard::from_bytes(&serialized[..]).expect("serialized hash is correct");

        assert_eq!(got, hash);
    }
}
