//! Adds "namespacing" semantics to proofs for the simple merkle tree, enabling
//! consumers to check that
//! - A range of leaves forms a complete namespace
//! - A range of leaves all exists in the same namespace
use crate::maybestd::{mem, vec::Vec};
use crate::{
    namespaced_hash::{NamespaceId, NamespaceMerkleHasher, NamespacedHash},
    simple_merkle::{
        db::NoopDb, error::RangeProofError, proof::Proof, tree::MerkleHash,
        utils::compute_num_left_siblings,
    },
    NamespaceMerkleTree,
};

/// A proof of some statement about a namespaced merkle tree.
///
/// This proof may prove the presence of some set of leaves, or the
/// absence of a particular namespace
#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum NamespaceProof<M: MerkleHash, const NS_ID_SIZE: usize> {
    /// A proof that some item is absent from the tree
    AbsenceProof {
        /// The range proof against the inner merkle tree
        proof: Proof<M>,
        /// Whether to treat the maximum possible namespace as a special marker value and ignore it in computing namespace ranges
        ignore_max_ns: bool,
        /// A leaf that *is* present in the tree, if the namespace being proven absent falls within
        /// the namespace range covered by the root.
        leaf: Option<NamespacedHash<NS_ID_SIZE>>,
    },
    /// A proof that some item is included in the tree
    PresenceProof {
        /// The range proof against the inner merkle tree
        proof: Proof<M>,
        /// Whether to treat the maximum possible namespace as a special marker value and ignore it in computing namespace ranges
        ignore_max_ns: bool,
    },
}

impl<M, const NS_ID_SIZE: usize> NamespaceProof<M, NS_ID_SIZE>
where
    M: NamespaceMerkleHasher<NS_ID_SIZE, Output = NamespacedHash<NS_ID_SIZE>>,
{
    /// Verify that the provided *raw* leaves are a complete namespace. This may be a proof of presence or absence.
    pub fn verify_complete_namespace(
        &self,
        root: &NamespacedHash<NS_ID_SIZE>,
        raw_leaves: &[impl AsRef<[u8]>],
        namespace: NamespaceId<NS_ID_SIZE>,
    ) -> Result<(), RangeProofError> {
        if self.is_of_presence() && raw_leaves.len() != self.range_len() {
            return Err(RangeProofError::WrongAmountOfLeavesProvided);
        }

        let tree = NamespaceMerkleTree::<NoopDb, M, NS_ID_SIZE>::with_hasher(
            M::with_ignore_max_ns(self.ignores_max_ns()),
        );
        tree.verify_namespace(root, raw_leaves, namespace, self)
    }

    /// Verify a that the provided *raw* leaves are a (1) present and (2) form a contiguous subset of some namespace
    pub fn verify_range(
        &self,
        root: &NamespacedHash<NS_ID_SIZE>,
        raw_leaves: &[impl AsRef<[u8]>],
        leaf_namespace: NamespaceId<NS_ID_SIZE>,
    ) -> Result<(), RangeProofError> {
        if self.is_of_absence() {
            return Err(RangeProofError::MalformedProof(
                "Cannot prove that a partial namespace is absent",
            ));
        };

        if raw_leaves.len() != self.range_len() {
            return Err(RangeProofError::WrongAmountOfLeavesProvided);
        }

        let leaf_hashes: Vec<_> = raw_leaves
            .iter()
            .map(|data| {
                M::with_ignore_max_ns(self.ignores_max_ns())
                    .hash_leaf_with_namespace(data.as_ref(), leaf_namespace)
            })
            .collect();
        let tree = NamespaceMerkleTree::<NoopDb, M, NS_ID_SIZE>::with_hasher(
            M::with_ignore_max_ns(self.ignores_max_ns()),
        );
        tree.inner.check_range_proof(
            root,
            &leaf_hashes,
            self.siblings(),
            self.start_idx() as usize,
        )
    }

    /// Narrows the proof range: uses an existing proof to create
    /// a new proof for a subrange of the original proof's range
    pub fn narrow_range<L: AsRef<[u8]>>(
        &self,
        left_extra_raw_leaves: &[L],
        right_extra_raw_leaves: &[L],
        leaf_namespace: NamespaceId<NS_ID_SIZE>,
    ) -> Result<Self, RangeProofError> {
        if self.is_of_absence() {
            return Err(RangeProofError::MalformedProof(
                "Cannot narrow the range of an absence proof",
            ));
        }

        let new_leaf_len = left_extra_raw_leaves.len() + right_extra_raw_leaves.len();
        if new_leaf_len >= self.range_len() {
            return Err(RangeProofError::WrongAmountOfLeavesProvided);
        }

        let leaves_to_hashes = |l: &[L]| -> Vec<NamespacedHash<NS_ID_SIZE>> {
            l.iter()
                .map(|data| {
                    M::with_ignore_max_ns(self.ignores_max_ns())
                        .hash_leaf_with_namespace(data.as_ref(), leaf_namespace)
                })
                .collect()
        };
        let left_extra_hashes = leaves_to_hashes(left_extra_raw_leaves);
        let right_extra_hashes = leaves_to_hashes(right_extra_raw_leaves);

        let mut tree = NamespaceMerkleTree::<NoopDb, M, NS_ID_SIZE>::with_hasher(
            M::with_ignore_max_ns(self.ignores_max_ns()),
        );

        let proof = tree.inner.narrow_range_proof(
            &left_extra_hashes,
            self.start_idx() as usize..(self.range_len() - new_leaf_len),
            &right_extra_hashes,
            &mut self.siblings(),
            self.start_idx() as usize,
        )?;

        Ok(Self::PresenceProof {
            proof,
            ignore_max_ns: self.ignores_max_ns(),
        })
    }

    /// Convert a proof of the presence of some leaf to the proof of the absence of another leaf
    pub fn convert_to_absence_proof(&mut self, leaf: NamespacedHash<NS_ID_SIZE>) {
        match self {
            NamespaceProof::AbsenceProof { .. } => {}
            NamespaceProof::PresenceProof {
                proof,
                ignore_max_ns,
            } => {
                let pf = mem::take(proof);
                *self = Self::AbsenceProof {
                    proof: pf,
                    ignore_max_ns: *ignore_max_ns,
                    leaf: Some(leaf),
                }
            }
        }
    }

    fn merkle_proof(&self) -> &Proof<M> {
        match self {
            NamespaceProof::AbsenceProof { proof, .. }
            | NamespaceProof::PresenceProof { proof, .. } => proof,
        }
    }

    /// Returns the siblings provided as part of the proof
    pub fn siblings(&self) -> &[NamespacedHash<NS_ID_SIZE>] {
        self.merkle_proof().siblings()
    }

    /// Returns the index of the first leaf in the proof
    pub fn start_idx(&self) -> u32 {
        self.merkle_proof().start_idx()
    }

    /// Returns the index *after* the last leaf in the proof
    pub fn end_idx(&self) -> u32 {
        self.merkle_proof().end_idx()
    }

    /// Returns the number of leaves covered by the proof
    fn range_len(&self) -> usize {
        self.merkle_proof().range_len()
    }

    /// Returns the leftmost node to the right of the proven range, if one exists
    pub fn leftmost_right_sibling(&self) -> Option<&NamespacedHash<NS_ID_SIZE>> {
        let siblings = self.siblings();
        let num_left_siblings = compute_num_left_siblings(self.start_idx() as usize);
        if siblings.len() > num_left_siblings {
            return Some(&siblings[num_left_siblings]);
        }
        None
    }

    /// Returns the rightmost node to the left of the proven range, if one exists
    pub fn rightmost_left_sibling(&self) -> Option<&NamespacedHash<NS_ID_SIZE>> {
        let siblings = self.siblings();
        let num_left_siblings = compute_num_left_siblings(self.start_idx() as usize);
        if num_left_siblings != 0 && num_left_siblings <= siblings.len() {
            return Some(&siblings[num_left_siblings - 1]);
        }
        None
    }

    fn ignores_max_ns(&self) -> bool {
        match self {
            Self::AbsenceProof { ignore_max_ns, .. }
            | Self::PresenceProof { ignore_max_ns, .. } => *ignore_max_ns,
        }
    }

    /// Returns true if the proof is an absence proof
    pub fn is_of_absence(&self) -> bool {
        match self {
            Self::AbsenceProof { .. } => true,
            Self::PresenceProof { .. } => false,
        }
    }

    /// Returns true if the proof is a presence proof
    pub fn is_of_presence(&self) -> bool {
        !self.is_of_absence()
    }
}
