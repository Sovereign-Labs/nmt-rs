#![no_main]

use libfuzzer_sys::{arbitrary, arbitrary::Unstructured, fuzz_target};
use nmt_rs::{simple_merkle::proof::Proof, NamespaceMerkleHasher};
use nmt_rs_fuzz::{inner, subrange, Hasher, TreeCase};

fn check(input: &mut Unstructured<'_>) -> arbitrary::Result<()> {
    let tamper: bool = input.arbitrary()?;
    let mut case = TreeCase::arbitrary(input, 32)?;
    let root = case.root.clone();
    let hasher = case.hasher();

    // Complete namespaces, present or absent
    let namespace = case.query(input)?;
    let expected = case.data_in(namespace);
    let (actual, proof) = case.tree.get_namespace_with_proof(namespace);
    assert_eq!(actual, expected);
    if case.hides(namespace) {
        // The max namespace lies outside the root's range, so it can only be proven absent
        assert!(proof.is_empty_proof() && proof.is_of_absence());
        assert!(proof
            .verify_complete_namespace(&root, &[] as &[Vec<u8>], namespace)
            .is_ok());
        assert_eq!(
            proof
                .verify_complete_namespace(&root, &expected, namespace)
                .is_ok(),
            expected.is_empty()
        );
    } else {
        assert!(proof
            .verify_complete_namespace(&root, &expected, namespace)
            .is_ok());
    }
    // The verifier's hasher must agree with the proof about the max namespace
    let mismatched = Hasher::with_ignore_max_ns(!case.ignore_max_ns);
    assert!(proof
        .verify_complete_namespace_with_hasher(&root, &expected, namespace, mismatched.clone())
        .is_err());
    assert!(proof
        .verify_range_with_hasher(&root, &expected, namespace, mismatched)
        .is_err());

    if !case.leaves.is_empty() {
        // A range within the queried namespace, or anywhere in the tree across several namespaces
        let within = case.range_of(namespace);
        let range = if !within.is_empty() && input.arbitrary()? {
            subrange(input, within)?
        } else {
            subrange(input, 0..case.leaves.len())?
        };
        let (actual, partial) = case.tree.get_range_with_proof(range.clone());
        assert_eq!(actual, case.data(range.clone()));

        // A merkle proof holds for leaves hashed under their own namespaces
        let leaf_hashes = case.leaf_hashes();
        let merkle_proof = Proof::<Hasher> {
            siblings: partial.siblings().to_vec(),
            range: range.start as u32..range.end as u32,
        };
        assert_eq!(&merkle_proof, inner(&partial));
        assert!(merkle_proof
            .verify_range_with_hasher(&root, &leaf_hashes[range.clone()], hasher.clone())
            .is_ok());

        // Namespace proofs hash every leaf under one namespace, so they hold only for ranges
        // within a single namespace, and are complete only if they cover all of it
        let first = case.leaves[range.start].0;
        let single = case.leaves[range.clone()]
            .iter()
            .all(|(ns, _)| *ns == first);
        assert_eq!(partial.verify_range(&root, &actual, first).is_ok(), single);
        let complete = single && case.range_of(first) == range && !case.hides(first);
        assert_eq!(
            partial
                .verify_complete_namespace(&root, &actual, first)
                .is_ok(),
            complete
        );

        // Single leaves
        let index = input.int_in_range(range.start..=range.end - 1)?;
        let (data, proof) = case.tree.get_index_with_proof(index);
        assert_eq!(data, case.leaves[index].1);
        assert!(proof
            .verify_range_with_hasher(&root, &leaf_hashes[index..index + 1], hasher.clone())
            .is_ok());
    }

    if tamper {
        let mut wrong = expected;
        if wrong.is_empty() {
            wrong.push(vec![0]);
        } else {
            wrong[0].push(0);
            assert!(proof.verify_range(&root, &wrong, namespace).is_err());
        }
        assert!(proof
            .verify_complete_namespace(&root, &wrong, namespace)
            .is_err());
    }

    // Leaves must be pushed in namespace order, and a rejected leaf leaves the tree unchanged
    if let Some((highest, _)) = case.leaves.last() {
        let lower = nmt_rs_fuzz::namespace(input)?;
        if lower < *highest {
            assert!(case.tree.push_leaf(b"late", lower).is_err());
            assert_eq!(case.tree.leaves().len(), case.leaves.len());
            assert_eq!(case.tree.root(), root);
        }
    }
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    let _ = check(&mut Unstructured::new(data));
});
