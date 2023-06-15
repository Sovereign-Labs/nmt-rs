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
pub enum NamespaceProof<M: MerkleHash> {
    AbsenceProof {
        proof: Proof<M>,
        ignore_max_ns: bool,
        leaf: Option<NamespacedHash>,
    },
    PresenceProof {
        proof: Proof<M>,
        ignore_max_ns: bool,
    },
}

impl<M: NamespaceMerkleHasher<Output = NamespacedHash>> NamespaceProof<M> {
    /// Verify that the provided *raw* leaves occur in the provided namespace, using this proof
    pub fn verify_complete_namespace(
        self,
        root: &NamespacedHash,
        raw_leaves: &[impl AsRef<[u8]>],
        namespace: NamespaceId,
    ) -> Result<(), RangeProofError> {
        let tree = NamespaceMerkleTree::<NoopDb, M>::with_hasher(M::with_ignore_max_ns(
            self.ignores_max_ns(),
        ));
        tree.verify_namespace(root, raw_leaves, namespace, self)
    }

    /// Verify a range proof
    pub fn verify_range(
        self,
        root: &NamespacedHash,
        raw_leaves: &[impl AsRef<[u8]>],
        leaf_namespace: NamespaceId,
    ) -> Result<(), RangeProofError> {
        let tree = NamespaceMerkleTree::<NoopDb, M>::with_hasher(M::with_ignore_max_ns(
            self.ignores_max_ns(),
        ));
        if let NamespaceProof::PresenceProof {
            proof: Proof {
                mut siblings,
                start_idx,
            },
            ..
        } = self
        {
            let leaf_hashes: Vec<NamespacedHash> = raw_leaves
                .iter()
                .map(|data| NamespacedHash::hash_leaf(data.as_ref(), leaf_namespace))
                .collect();
            tree.inner
                .check_range_proof(root, &leaf_hashes, &mut siblings, start_idx as usize)?;
            Ok(())
        } else {
            Err(RangeProofError::MalformedProof)
        }
    }
    pub fn convert_to_absence_proof(&mut self, leaf: NamespacedHash) {
        match self {
            NamespaceProof::AbsenceProof { .. } => {}
            NamespaceProof::PresenceProof {
                proof,
                ignore_max_ns,
            } => {
                let pf = std::mem::take(proof);
                *self = Self::AbsenceProof {
                    proof: pf,
                    ignore_max_ns: *ignore_max_ns,
                    leaf: Some(leaf),
                }
            }
        }
    }

    pub fn siblings(&self) -> &Vec<NamespacedHash> {
        match self {
            NamespaceProof::AbsenceProof {
                proof: Proof { siblings, .. },
                ..
            } => siblings,
            NamespaceProof::PresenceProof {
                proof: Proof { siblings, .. },
                ..
            } => siblings,
        }
    }

    pub fn start_idx(&self) -> u32 {
        match self {
            NamespaceProof::AbsenceProof {
                proof:
                    Proof {
                        siblings: _,
                        start_idx,
                    },
                ..
            } => *start_idx,
            NamespaceProof::PresenceProof {
                proof:
                    Proof {
                        siblings: _,
                        start_idx,
                    },
                ..
            } => *start_idx,
        }
    }
    pub fn leftmost_right_sibling(&self) -> Option<&NamespacedHash> {
        let siblings = self.siblings();
        let num_left_siblings = compute_num_left_siblings(self.start_idx() as usize);
        if siblings.len() > num_left_siblings {
            return Some(&siblings[num_left_siblings]);
        }
        None
    }

    pub fn rightmost_left_sibling(&self) -> Option<&NamespacedHash> {
        let siblings = self.siblings();
        let num_left_siblings = compute_num_left_siblings(self.start_idx() as usize);
        if num_left_siblings != 0 && num_left_siblings <= siblings.len() {
            return Some(&siblings[num_left_siblings - 1]);
        }
        None
    }

    #[cfg(test)]
    pub fn take_siblings(self) -> Vec<NamespacedHash> {
        match self {
            Self::AbsenceProof {
                proof: Proof { siblings, .. },
                ..
            } => siblings,
            Self::PresenceProof {
                proof: Proof { siblings, .. },
                ..
            } => siblings,
        }
    }

    fn ignores_max_ns(&self) -> bool {
        match self {
            Self::AbsenceProof {
                proof: _,
                ignore_max_ns,
                ..
            } => *ignore_max_ns,
            Self::PresenceProof {
                proof: _,
                ignore_max_ns,
                ..
            } => *ignore_max_ns,
        }
    }

    pub fn is_of_absence(&self) -> bool {
        match self {
            Self::AbsenceProof { .. } => true,
            Self::PresenceProof { .. } => false,
        }
    }
}
