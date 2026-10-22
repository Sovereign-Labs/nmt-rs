use nmt_rs::{
    CelestiaNmt, NamespaceId, NamespaceMerkleHasher, NamespaceProof, NamespacedHash,
    NamespacedSha2Hasher,
};

#[test]
fn unordered_sibling_is_rejected_without_panicking() {
    let mut tree = CelestiaNmt::with_hasher(NamespacedSha2Hasher::with_ignore_max_ns(false));
    tree.push_leaf(b"left", NamespaceId([0; 29])).unwrap();
    tree.push_leaf(b"right", NamespaceId([1; 29])).unwrap();
    let root = tree.root();
    let (leaves, mut proof) = tree.get_namespace_with_proof(NamespaceId([1; 29]));
    let NamespaceProof::PresenceProof { proof: inner, .. } = &mut proof else {
        panic!("expected presence proof");
    };
    inner.siblings[0] = NamespacedHash::new(
        NamespaceId([0; 29]),
        NamespaceId([2; 29]),
        inner.siblings[0].hash(),
    );
    assert!(proof
        .verify_range(&root, &leaves, NamespaceId([1; 29]))
        .is_err());
}

#[test]
fn absence_proof_rejects_fabricated_data() {
    for ignore_max_ns in [false, true] {
        for empty in [false, true] {
            let mut tree =
                CelestiaNmt::with_hasher(NamespacedSha2Hasher::with_ignore_max_ns(ignore_max_ns));
            if !empty {
                tree.push_leaf(b"present", NamespaceId([0; 29])).unwrap();
            }
            let root = tree.root();
            let namespace = NamespaceId([1; 29]);
            let proof = tree.get_namespace_proof(namespace);
            assert!(proof
                .verify_complete_namespace(&root, &[b"fabricated"], namespace)
                .is_err());
        }
    }
}

/// A proof's start index fixes how many left siblings it must carry: one per set bit
/// (`compute_num_left_siblings`). Stripping the siblings from an honest proof leaves the
/// start index promising nodes that aren't there; the verifier must reject, not index past the end.
#[test]
fn proof_without_left_siblings_is_rejected_without_panicking() {
    let mut tree = CelestiaNmt::with_hasher(NamespacedSha2Hasher::with_ignore_max_ns(true));
    for ns in [1, 3, 5, 5] {
        tree.push_leaf(&[ns], NamespaceId([ns; 29])).unwrap();
    }
    let root = tree.root();

    // Absence of namespace 4 is proven by the leaf at index 2 (namespace 5), which needs one left sibling.
    let mut absence = tree.get_namespace_proof(NamespaceId([4; 29]));
    let NamespaceProof::AbsenceProof { proof, .. } = &mut absence else {
        panic!("expected absence proof");
    };
    assert_eq!(proof.range.start, 2);
    proof.siblings.clear();
    let no_leaves: &[&[u8]] = &[];
    assert!(absence
        .verify_complete_namespace(&root, no_leaves, NamespaceId([4; 29]))
        .is_err());

    // Namespace 5 occupies indices 2..4, which also needs one left sibling.
    let (leaves, mut presence) = tree.get_namespace_with_proof(NamespaceId([5; 29]));
    let NamespaceProof::PresenceProof { proof, .. } = &mut presence else {
        panic!("expected presence proof");
    };
    assert_eq!(proof.range, 2..4);
    proof.siblings.clear();
    assert!(presence
        .verify_complete_namespace(&root, &leaves, NamespaceId([5; 29]))
        .is_err());
}
