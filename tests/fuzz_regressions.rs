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
