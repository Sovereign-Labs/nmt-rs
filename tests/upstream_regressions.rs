use nmt_rs::{
    simple_merkle::{error::RangeProofError, proof::Proof, tree::MerkleHash},
    NamespaceId, NamespaceMerkleHasher, NamespaceMerkleTree, NamespaceProof, NamespacedHash,
    NamespacedSha2Hasher,
};

type Hasher<const N: usize> = NamespacedSha2Hasher<N>;
type Tree<const N: usize> = NamespaceMerkleTree<Hasher<N>, N>;

const NO_LEAVES: &[&[u8]] = &[];

fn tree<const N: usize>(namespaces: &[u8], ignore_max_ns: bool) -> Tree<N> {
    let mut tree = Tree::with_hasher(Hasher::with_ignore_max_ns(ignore_max_ns));
    for &namespace in namespaces {
        tree.push_leaf(b"leaf", NamespaceId([namespace; N]))
            .unwrap();
    }
    tree
}

fn merkle_proof<const N: usize>(proof: &mut NamespaceProof<Hasher<N>, N>) -> &mut Proof<Hasher<N>> {
    match proof {
        NamespaceProof::PresenceProof { proof, .. }
        | NamespaceProof::AbsenceProof { proof, .. } => proof,
    }
}

fn leaf<const N: usize>(namespace: u8) -> NamespacedHash<N> {
    Hasher::with_ignore_max_ns(false).hash_leaf_with_namespace(b"leaf", NamespaceId([namespace; N]))
}

fn empty_proof() -> NamespaceProof<Hasher<1>, 1> {
    NamespaceProof::AbsenceProof {
        proof: Proof::default(),
        ignore_max_ns: true,
        leaf: None,
    }
}

fn malformed_empty_proof() -> NamespaceProof<Hasher<1>, 1> {
    let mut proof = tree::<1>(&[1, 2, 3, 4], true).get_namespace_proof(NamespaceId([1]));
    merkle_proof(&mut proof).range = 0..0;
    proof
}

// Port of TestVerifyNamespace_EmptyProof:
// https://github.com/celestiaorg/nmt/blob/a94d705f3ec953f848cfcfb0cc048c0e690f00d8/proof_test.go#L43-L104
#[test]
fn empty_proof_accepts_absent_namespace_and_empty_leaves() {
    let root = tree::<1>(&[1, 2, 3, 4], true).root();
    assert!(empty_proof()
        .verify_complete_namespace(&root, NO_LEAVES, NamespaceId([0]))
        .is_ok());
}

// Port of TestVerifyNamespace_EmptyProof:
// https://github.com/celestiaorg/nmt/blob/a94d705f3ec953f848cfcfb0cc048c0e690f00d8/proof_test.go#L43-L104
#[test]
fn empty_proof_rejects_extra_siblings_for_present_namespace() {
    let root = tree::<1>(&[1, 2, 3, 4], true).root();
    assert!(malformed_empty_proof()
        .verify_complete_namespace(&root, NO_LEAVES, NamespaceId([1]))
        .is_err());
}

// Port of TestVerifyNamespace_EmptyProof:
// https://github.com/celestiaorg/nmt/blob/a94d705f3ec953f848cfcfb0cc048c0e690f00d8/proof_test.go#L43-L104
#[test]
fn empty_proof_rejects_nonempty_leaves_for_absent_namespace() {
    let root = tree::<1>(&[1, 2, 3, 4], true).root();
    assert!(empty_proof()
        .verify_complete_namespace(&root, &[b"fabricated"], NamespaceId([0]))
        .is_err());
}

// Port of TestVerifyNamespace_EmptyProof:
// https://github.com/celestiaorg/nmt/blob/a94d705f3ec953f848cfcfb0cc048c0e690f00d8/proof_test.go#L43-L104
#[test]
fn empty_proof_rejects_present_namespace() {
    let root = tree::<1>(&[1, 2, 3, 4], true).root();
    assert!(empty_proof()
        .verify_complete_namespace(&root, NO_LEAVES, NamespaceId([1]))
        .is_err());
}

// Port of TestVerifyNamespace_EmptyProof:
// https://github.com/celestiaorg/nmt/blob/a94d705f3ec953f848cfcfb0cc048c0e690f00d8/proof_test.go#L43-L104
#[test]
fn empty_proof_accepts_empty_tree_and_empty_leaves() {
    assert!(empty_proof()
        .verify_complete_namespace(&Hasher::<1>::EMPTY_ROOT, NO_LEAVES, NamespaceId([0]))
        .is_ok());
}

// Port of TestVerifyNamespace_EmptyProof:
// https://github.com/celestiaorg/nmt/blob/a94d705f3ec953f848cfcfb0cc048c0e690f00d8/proof_test.go#L43-L104
#[test]
fn empty_proof_rejects_extra_siblings_for_empty_tree() {
    assert!(malformed_empty_proof()
        .verify_complete_namespace(&Hasher::<1>::EMPTY_ROOT, NO_LEAVES, NamespaceId([1]))
        .is_err());
}

// Port of TestVerifyNamespace_EmptyProof:
// https://github.com/celestiaorg/nmt/blob/a94d705f3ec953f848cfcfb0cc048c0e690f00d8/proof_test.go#L43-L104
#[test]
fn empty_proof_rejects_nonempty_leaves_for_empty_tree() {
    assert!(empty_proof()
        .verify_complete_namespace(&Hasher::<1>::EMPTY_ROOT, &[b"fabricated"], NamespaceId([0]))
        .is_err());
}

// Extension of TestVerifyNamespace_EmptyProof for Rust's saturating range length:
// https://github.com/celestiaorg/nmt/blob/a94d705f3ec953f848cfcfb0cc048c0e690f00d8/proof_test.go#L43-L104
#[test]
fn empty_tree_rejects_reversed_presence_range_with_siblings() {
    let mut proof = malformed_empty_proof();
    merkle_proof(&mut proof).range.start = 9;
    assert!(proof
        .verify_complete_namespace(&Hasher::<1>::EMPTY_ROOT, NO_LEAVES, NamespaceId([1]))
        .is_err());
}

// Adapted from TestValidateCompleteness_TruncatedProof_RejectsEmptyNodes:
// https://github.com/celestiaorg/nmt/blob/a94d705f3ec953f848cfcfb0cc048c0e690f00d8/proof_completeness_test.go#L16-L33
#[test]
fn completeness_rejects_empty_siblings_at_nonzero_start() {
    let mut tree = tree::<1>(&[1, 1, 1, 1, 1, 1, 1, 1, 5, 6], false);
    let (leaves, mut proof) = tree.get_namespace_with_proof(NamespaceId([5]));
    assert_eq!(proof.start_idx(), 8);
    merkle_proof(&mut proof).siblings.clear();
    assert!(proof
        .verify_complete_namespace(&tree.root(), &leaves, NamespaceId([5]))
        .is_err());
}

// Multi-leaf extension of TestValidateCompleteness_TruncatedProof_RejectsEmptyNodes:
// https://github.com/celestiaorg/nmt/blob/a94d705f3ec953f848cfcfb0cc048c0e690f00d8/proof_completeness_test.go#L16-L33
#[test]
fn completeness_rejects_empty_siblings_for_multiple_leaves() {
    let mut tree = tree::<1>(&[1, 1, 1, 1, 1, 1, 1, 1, 5, 5, 6], false);
    let (leaves, mut proof) = tree.get_namespace_with_proof(NamespaceId([5]));
    assert_eq!(proof.start_idx(), 8);
    merkle_proof(&mut proof).siblings.clear();
    assert!(proof
        .verify_complete_namespace(&tree.root(), &leaves, NamespaceId([5]))
        .is_err());
}

// Absence extension of TestValidateCompleteness_TruncatedProof_RejectsEmptyNodes:
// https://github.com/celestiaorg/nmt/blob/a94d705f3ec953f848cfcfb0cc048c0e690f00d8/proof_completeness_test.go#L16-L33
#[test]
fn absence_rejects_empty_siblings_at_nonzero_start() {
    let mut tree = tree::<1>(&[1, 1, 1, 1, 1, 1, 1, 1, 5, 6], false);
    let mut proof = tree.get_namespace_proof(NamespaceId([4]));
    assert_eq!(proof.start_idx(), 8);
    merkle_proof(&mut proof).siblings.clear();
    assert!(proof
        .verify_complete_namespace(&tree.root(), NO_LEAVES, NamespaceId([4]))
        .is_err());
}

// Adapted from TestValidateCompleteness_TruncatedProof_RejectsInsufficientNodes:
// https://github.com/celestiaorg/nmt/blob/a94d705f3ec953f848cfcfb0cc048c0e690f00d8/proof_completeness_test.go#L38-L67
#[test]
fn completeness_rejects_insufficient_siblings() {
    let mut tree = tree::<1>(&[1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 5, 6], false);
    let (leaves, mut proof) = tree.get_namespace_with_proof(NamespaceId([5]));
    assert_eq!(proof.start_idx(), 12);
    merkle_proof(&mut proof).siblings.truncate(1);
    assert!(proof
        .verify_complete_namespace(&tree.root(), &leaves, NamespaceId([5]))
        .is_err());
}

// Absence extension of TestValidateCompleteness_TruncatedProof_RejectsInsufficientNodes:
// https://github.com/celestiaorg/nmt/blob/a94d705f3ec953f848cfcfb0cc048c0e690f00d8/proof_completeness_test.go#L38-L67
#[test]
fn absence_rejects_insufficient_siblings() {
    let mut tree = tree::<1>(&[1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 5, 6], false);
    let mut proof = tree.get_namespace_proof(NamespaceId([4]));
    assert_eq!(proof.start_idx(), 12);
    merkle_proof(&mut proof).siblings.truncate(1);
    assert!(proof
        .verify_complete_namespace(&tree.root(), NO_LEAVES, NamespaceId([4]))
        .is_err());
}

// Adapted from TestValidateCompleteness_RightSideCheck_StillRejectsSmallNamespace:
// https://github.com/celestiaorg/nmt/blob/a94d705f3ec953f848cfcfb0cc048c0e690f00d8/proof_completeness_test.go#L74-L96
#[test]
fn completeness_rejects_smaller_namespace_on_right() {
    let mut tree = tree::<1>(&[5, 6], false);
    let (leaves, mut proof) = tree.get_namespace_with_proof(NamespaceId([5]));
    merkle_proof(&mut proof).siblings[0] = leaf(1);
    assert!(proof
        .verify_complete_namespace(&tree.root(), &leaves, NamespaceId([5]))
        .is_err());
}

// Equal-namespace extension of TestValidateCompleteness_RightSideCheck_StillRejectsSmallNamespace:
// https://github.com/celestiaorg/nmt/blob/a94d705f3ec953f848cfcfb0cc048c0e690f00d8/proof_completeness_test.go#L74-L96
#[test]
fn completeness_rejects_omitted_leaf_of_same_namespace_on_right() {
    let mut tree = tree::<1>(&[5, 5], false);
    let (leaves, proof) = tree.get_range_with_proof(0..1);
    assert!(proof
        .verify_range(&tree.root(), &leaves, NamespaceId([5]))
        .is_ok());
    assert!(proof
        .verify_complete_namespace(&tree.root(), &leaves, NamespaceId([5]))
        .is_err());
}

// Decode-boundary adaptation of TestVerifyLeafHashes_Err ("corrupt root"):
// https://github.com/celestiaorg/nmt/blob/a94d705f3ec953f848cfcfb0cc048c0e690f00d8/proof_test.go#L324-L406
#[test]
fn leaf_hash_verification_rejects_truncated_root_encoding() {
    let root: Vec<_> = tree::<2>(&[1, 2, 3, 4, 5, 6, 7, 8], true)
        .root()
        .iter()
        .collect();
    assert!(NamespacedHash::<2>::try_from(&root[..root.len() - 1]).is_err());
}

// Decode-boundary adaptation of TestVerifyLeafHashes_Err ("wrong leafHash: not namespaced"):
// https://github.com/celestiaorg/nmt/blob/a94d705f3ec953f848cfcfb0cc048c0e690f00d8/proof_test.go#L324-L406
#[test]
fn leaf_hash_verification_rejects_truncated_leaf_encoding() {
    let hash: Vec<_> = leaf::<2>(5).iter().collect();
    assert!(NamespacedHash::<2>::try_from(&hash[..2]).is_err());
}

// Adapted from TestVerifyLeafHashes_Err ("wrong leafHash: smaller namespace"):
// https://github.com/celestiaorg/nmt/blob/a94d705f3ec953f848cfcfb0cc048c0e690f00d8/proof_test.go#L324-L406
#[test]
fn leaf_hash_verification_rejects_smaller_namespace() {
    let mut tree = tree::<2>(&[1, 2, 3, 4, 5, 6, 7, 8], true);
    let proof = tree.build_range_proof(4..5);
    let corrupted = NamespacedHash::new(
        NamespaceId([3; 2]),
        NamespaceId([3; 2]),
        leaf::<2>(5).hash(),
    );
    assert!(proof
        .verify_range_with_hasher(&tree.root(), &[corrupted], Hasher::with_ignore_max_ns(true))
        .is_err());
}

// Adapted from TestVerifyLeafHashes_Err ("wrong leafHash: bigger namespace"):
// https://github.com/celestiaorg/nmt/blob/a94d705f3ec953f848cfcfb0cc048c0e690f00d8/proof_test.go#L324-L406
#[test]
fn leaf_hash_verification_rejects_larger_namespace() {
    let mut tree = tree::<2>(&[1, 2, 3, 4, 5, 6, 7, 8], true);
    let proof = tree.build_range_proof(4..5);
    let corrupted = NamespacedHash::new(
        NamespaceId([7; 2]),
        NamespaceId([7; 2]),
        leaf::<2>(5).hash(),
    );
    assert!(proof
        .verify_range_with_hasher(&tree.root(), &[corrupted], Hasher::with_ignore_max_ns(true))
        .is_err());
}

// Decode-boundary adaptation of TestVerifyLeafHashes_Err ("wrong proof.nodes"):
// https://github.com/celestiaorg/nmt/blob/a94d705f3ec953f848cfcfb0cc048c0e690f00d8/proof_test.go#L324-L406
#[test]
fn leaf_hash_verification_rejects_truncated_sibling_encoding() {
    let mut tree = tree::<2>(&[1, 2, 3, 4, 5, 6, 7, 8], true);
    let proof = tree.build_range_proof(3..4);
    let sibling: Vec<_> = proof.siblings[2].iter().collect();
    assert!(NamespacedHash::<2>::try_from(&sibling[..1]).is_err());
}

// Port of TestVerifyLeafHashes_Err ("wrong proof range: start = end"):
// https://github.com/celestiaorg/nmt/blob/a94d705f3ec953f848cfcfb0cc048c0e690f00d8/proof_test.go#L324-L406
#[test]
fn presence_rejects_empty_range_with_leaf() {
    let mut tree = tree::<2>(&[1, 2, 3, 4, 5, 6, 7, 8], true);
    let (leaves, mut proof) = tree.get_namespace_with_proof(NamespaceId([4; 2]));
    merkle_proof(&mut proof).range = 0..0;
    assert!(proof
        .verify_complete_namespace(&tree.root(), &leaves, NamespaceId([4; 2]))
        .is_err());
}

// Port of TestVerifyLeafHashes_Err ("wrong proof range: start > end"):
// https://github.com/celestiaorg/nmt/blob/a94d705f3ec953f848cfcfb0cc048c0e690f00d8/proof_test.go#L324-L406
// Its negative-start case is unrepresentable in Rust's Range<u32>.
#[test]
fn presence_rejects_reversed_range_with_leaf() {
    let mut tree = tree::<2>(&[1, 2, 3, 4, 5, 6, 7, 8], true);
    let (leaves, mut proof) = tree.get_namespace_with_proof(NamespaceId([4; 2]));
    merkle_proof(&mut proof).range.start = proof.end_idx() + 1;
    assert!(proof
        .verify_complete_namespace(&tree.root(), &leaves, NamespaceId([4; 2]))
        .is_err());
}

// Absence extension of TestVerifyLeafHashes_Err:
// https://github.com/celestiaorg/nmt/blob/a94d705f3ec953f848cfcfb0cc048c0e690f00d8/proof_test.go#L324-L406
#[test]
fn absence_rejects_empty_range_with_witness() {
    let mut tree = tree::<1>(&[1, 2, 2, 4], true);
    let mut proof = tree.get_namespace_proof(NamespaceId([3]));
    merkle_proof(&mut proof).range.end = proof.start_idx();
    assert!(proof
        .verify_complete_namespace(&tree.root(), NO_LEAVES, NamespaceId([3]))
        .is_err());
}

// Absence extension of TestVerifyLeafHashes_Err:
// https://github.com/celestiaorg/nmt/blob/a94d705f3ec953f848cfcfb0cc048c0e690f00d8/proof_test.go#L324-L406
#[test]
fn absence_rejects_reversed_range_with_witness() {
    let mut tree = tree::<1>(&[1, 2, 2, 4], true);
    let mut proof = tree.get_namespace_proof(NamespaceId([3]));
    merkle_proof(&mut proof).range.end = 0;
    assert!(proof
        .verify_complete_namespace(&tree.root(), NO_LEAVES, NamespaceId([3]))
        .is_err());
}

// Absence extension of TestVerifyLeafHashes_Err's range/leaf-count validation:
// https://github.com/celestiaorg/nmt/blob/a94d705f3ec953f848cfcfb0cc048c0e690f00d8/proof_test.go#L324-L406
#[test]
fn absence_rejects_range_larger_than_witness() {
    let mut tree = tree::<1>(&[1, 2, 2, 4], true);
    let mut proof = tree.get_namespace_proof(NamespaceId([3]));
    merkle_proof(&mut proof).range.end += 1;
    assert!(proof
        .verify_complete_namespace(&tree.root(), NO_LEAVES, NamespaceId([3]))
        .is_err());
}

// Port of TestHashNode_ErrorsCheck ("left.maxNs<right.minNs"):
// https://github.com/celestiaorg/nmt/blob/a94d705f3ec953f848cfcfb0cc048c0e690f00d8/hasher_test.go#L472-L543
#[test]
fn hash_node_accepts_ordered_namespaces() {
    let left = NamespacedHash::new(NamespaceId([0; 2]), NamespaceId([1; 2]), [1; 32]);
    let right = NamespacedHash::new(NamespaceId([2; 2]), NamespaceId([3; 2]), [1; 32]);
    let root = Hasher::with_ignore_max_ns(false).hash_nodes(&left, &right);
    assert_eq!(root.min_namespace(), left.min_namespace());
    assert_eq!(root.max_namespace(), right.max_namespace());
}

// Port of TestHashNode_ErrorsCheck ("left.maxNs=right.minNs"):
// https://github.com/celestiaorg/nmt/blob/a94d705f3ec953f848cfcfb0cc048c0e690f00d8/hasher_test.go#L472-L543
#[test]
fn hash_node_accepts_equal_namespace_boundary() {
    let left = NamespacedHash::new(NamespaceId([0; 2]), NamespaceId([1; 2]), [1; 32]);
    let right = NamespacedHash::new(NamespaceId([1; 2]), NamespaceId([2; 2]), [1; 32]);
    let root = Hasher::with_ignore_max_ns(false).hash_nodes(&left, &right);
    assert_eq!(root.min_namespace(), left.min_namespace());
    assert_eq!(root.max_namespace(), right.max_namespace());
}

// Verifier adaptation of TestHashNode_ErrorsCheck ("left.maxNs>right.minNs"):
// https://github.com/celestiaorg/nmt/blob/a94d705f3ec953f848cfcfb0cc048c0e690f00d8/hasher_test.go#L472-L543
#[test]
fn range_verification_rejects_unordered_siblings() {
    let mut tree = tree::<1>(&[1, 2, 3, 4], false);
    let (leaves, mut proof) = tree.get_namespace_with_proof(NamespaceId([2]));
    merkle_proof(&mut proof).siblings[0] = leaf(3);
    assert!(proof
        .verify_range(&tree.root(), &leaves, NamespaceId([2]))
        .is_err());
}

// Verifier adaptation of TestHashNode_ErrorsCheck ("left.maxNs>right.minNs"):
// https://github.com/celestiaorg/nmt/blob/a94d705f3ec953f848cfcfb0cc048c0e690f00d8/hasher_test.go#L472-L543
#[test]
fn complete_namespace_verification_rejects_unordered_siblings() {
    let mut tree = tree::<1>(&[1, 2, 3, 4], false);
    let (leaves, mut proof) = tree.get_namespace_with_proof(NamespaceId([2]));
    merkle_proof(&mut proof).siblings[0] = leaf(3);
    assert!(proof
        .verify_complete_namespace(&tree.root(), &leaves, NamespaceId([2]))
        .is_err());
}

// Decode-boundary adaptation of TestHashNode_ErrorsCheck ("len(left)<hasher.Size"):
// https://github.com/celestiaorg/nmt/blob/a94d705f3ec953f848cfcfb0cc048c0e690f00d8/hasher_test.go#L472-L543
#[test]
fn hash_node_rejects_truncated_left_encoding() {
    assert!(NamespacedHash::<2>::try_from([0, 0, 1].as_slice()).is_err());
}

// Decode-boundary adaptation of TestHashNode_ErrorsCheck ("len(right)<hasher.Size"):
// https://github.com/celestiaorg/nmt/blob/a94d705f3ec953f848cfcfb0cc048c0e690f00d8/hasher_test.go#L472-L543
#[test]
fn hash_node_rejects_truncated_right_encoding() {
    assert!(NamespacedHash::<2>::try_from([2, 2, 3].as_slice()).is_err());
}

struct ConfiguredHasher {
    inner: Hasher<1>,
    salt: u8,
}

impl MerkleHash for ConfiguredHasher {
    type Output = NamespacedHash<1>;
    const EMPTY_ROOT: Self::Output = Hasher::<1>::EMPTY_ROOT;

    fn hash_leaf(&self, data: &[u8]) -> Self::Output {
        self.hash_leaf_with_namespace(&data[1..], NamespaceId([data[0]]))
    }

    fn hash_nodes(&self, left: &Self::Output, right: &Self::Output) -> Self::Output {
        self.inner.hash_nodes(left, right)
    }

    fn try_hash_nodes(
        &self,
        left: &Self::Output,
        right: &Self::Output,
    ) -> Result<Self::Output, RangeProofError> {
        self.inner.try_hash_nodes(left, right)
    }
}

impl NamespaceMerkleHasher<1> for ConfiguredHasher {
    fn with_ignore_max_ns(ignore_max_ns: bool) -> Self {
        Self {
            inner: Hasher::with_ignore_max_ns(ignore_max_ns),
            salt: 0,
        }
    }

    fn ignores_max_ns(&self) -> bool {
        self.inner.ignores_max_ns()
    }

    fn hash_leaf_with_namespace(&self, data: &[u8], namespace: NamespaceId<1>) -> Self::Output {
        let mut salted = vec![self.salt];
        salted.extend_from_slice(data);
        self.inner.hash_leaf_with_namespace(&salted, namespace)
    }
}

// Original Rust regression; Go's related TestCustomHasher checks only the stored type:
// https://github.com/celestiaorg/nmt/blob/a94d705f3ec953f848cfcfb0cc048c0e690f00d8/nmt_test.go#L564-L575
#[test]
fn custom_hasher_preserves_configuration_for_singleton_root() {
    let hasher = ConfiguredHasher {
        inner: Hasher::with_ignore_max_ns(true),
        salt: 42,
    };
    let expected = hasher.hash_leaf_with_namespace(b"leaf", NamespaceId([1]));
    let mut tree = NamespaceMerkleTree::<_, 1>::with_hasher(hasher);
    tree.push_leaf(b"leaf", NamespaceId([1])).unwrap();
    assert_eq!(tree.root(), expected);
}

// Original Rust regression; Go's related TestCustomHasher checks only the stored type:
// https://github.com/celestiaorg/nmt/blob/a94d705f3ec953f848cfcfb0cc048c0e690f00d8/nmt_test.go#L564-L575
#[test]
fn custom_hasher_preserves_configuration_for_two_leaf_root() {
    let hasher = ConfiguredHasher {
        inner: Hasher::with_ignore_max_ns(true),
        salt: 42,
    };
    let left = hasher.hash_leaf_with_namespace(b"leaf", NamespaceId([1]));
    let right = hasher.hash_leaf_with_namespace(b"leaf", NamespaceId([2]));
    let expected = hasher.hash_nodes(&left, &right);
    let mut tree = NamespaceMerkleTree::<_, 1>::with_hasher(hasher);
    tree.push_leaf(b"leaf", NamespaceId([1])).unwrap();
    tree.push_leaf(b"leaf", NamespaceId([2])).unwrap();
    assert_eq!(tree.root(), expected);
}

// Original Rust regression: proofs from a tree with a configured hasher verify with that hasher.
#[test]
fn custom_hasher_proofs_verify_with_hasher() {
    let hasher = || ConfiguredHasher {
        inner: Hasher::with_ignore_max_ns(true),
        salt: 42,
    };
    let mut tree = NamespaceMerkleTree::<_, 1>::with_hasher(hasher());
    for namespace in [1, 2, 2, 4] {
        tree.push_leaf(b"leaf", NamespaceId([namespace])).unwrap();
    }
    let root = tree.root();

    let (leaves, proof) = tree.get_namespace_with_proof(NamespaceId([2]));
    assert!(proof
        .verify_complete_namespace_with_hasher(&root, &leaves, NamespaceId([2]), hasher())
        .is_ok());
    assert!(proof
        .verify_range_with_hasher(&root, &leaves, NamespaceId([2]), hasher())
        .is_ok());
    // The default hasher for the proof drops the salt, so it computes a different root
    assert!(proof
        .verify_complete_namespace(&root, &leaves, NamespaceId([2]))
        .is_err());

    let proof = tree.get_namespace_proof(NamespaceId([3]));
    assert!(proof
        .verify_complete_namespace_with_hasher(&root, NO_LEAVES, NamespaceId([3]), hasher())
        .is_ok());
}

// Original Rust regression: the verifier's hasher must agree with the proof on ignoring the max namespace.
#[test]
fn verification_rejects_hasher_with_mismatched_ignore_max_ns() {
    let mut tree = tree::<1>(&[1, 2, 3, 4], true);
    let (leaves, proof) = tree.get_namespace_with_proof(NamespaceId([2]));
    assert!(proof
        .verify_complete_namespace_with_hasher(
            &tree.root(),
            &leaves,
            NamespaceId([2]),
            Hasher::with_ignore_max_ns(false),
        )
        .is_err());
}
