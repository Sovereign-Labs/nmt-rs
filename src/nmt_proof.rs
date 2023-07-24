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
    AbsenceProof {
        proof: Proof<M>,
        ignore_max_ns: bool,
        leaf: Option<NamespacedHash<NS_ID_SIZE>>,
    },
    PresenceProof {
        proof: Proof<M>,
        ignore_max_ns: bool,
    },
}

impl<M, const NS_ID_SIZE: usize> NamespaceProof<M, NS_ID_SIZE>
where
    M: NamespaceMerkleHasher<Output = NamespacedHash<NS_ID_SIZE>>,
{
    /// Verify that the provided *raw* leaves occur in the provided namespace, using this proof
    pub fn verify_complete_namespace(
        &self,
        root: &NamespacedHash<NS_ID_SIZE>,
        raw_leaves: &[impl AsRef<[u8]>],
        namespace: NamespaceId<NS_ID_SIZE>,
    ) -> Result<(), RangeProofError> {
        let tree = NamespaceMerkleTree::<NoopDb, M, NS_ID_SIZE>::with_hasher(
            M::with_ignore_max_ns(self.ignores_max_ns()),
        );
        tree.verify_namespace(root, raw_leaves, namespace, self)
    }

    /// Verify a range proof
    pub fn verify_range(
        &self,
        root: &NamespacedHash<NS_ID_SIZE>,
        raw_leaves: &[impl AsRef<[u8]>],
        leaf_namespace: NamespaceId<NS_ID_SIZE>,
    ) -> Result<(), RangeProofError> {
        if self.is_of_absence() {
            return Err(RangeProofError::MalformedProof);
        };

        let leaf_hashes: Vec<_> = raw_leaves
            .iter()
            .map(|data| NamespacedHash::hash_leaf(data.as_ref(), leaf_namespace))
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

    pub fn siblings(&self) -> &[NamespacedHash<NS_ID_SIZE>] {
        self.merkle_proof().siblings()
    }

    pub fn start_idx(&self) -> u32 {
        self.merkle_proof().start_idx()
    }

    pub fn leftmost_right_sibling(&self) -> Option<&NamespacedHash<NS_ID_SIZE>> {
        let siblings = self.siblings();
        let num_left_siblings = compute_num_left_siblings(self.start_idx() as usize);
        if siblings.len() > num_left_siblings {
            return Some(&siblings[num_left_siblings]);
        }
        None
    }

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

    pub fn is_of_absence(&self) -> bool {
        match self {
            Self::AbsenceProof { .. } => true,
            Self::PresenceProof { .. } => false,
        }
    }

    pub fn is_of_presence(&self) -> bool {
        !self.is_of_absence()
    }
}
