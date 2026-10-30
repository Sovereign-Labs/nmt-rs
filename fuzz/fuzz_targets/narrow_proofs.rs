#![no_main]

use libfuzzer_sys::{arbitrary, arbitrary::Unstructured, fuzz_target};
use nmt_rs::NamespaceMerkleHasher;
use nmt_rs_fuzz::{
    inner, malformed_proof, namespace, namespaced_hash, raw_leaves, subrange, Hasher, NsProof,
    TreeCase,
};

/// Narrowing an honest proof must give the proof the tree builds for the narrower range.
fn honest(input: &mut Unstructured<'_>) -> arbitrary::Result<()> {
    let mut case = TreeCase::arbitrary(input, 64)?;
    if case.leaves.is_empty() {
        return Ok(());
    }
    let hasher = case.hasher();
    let range = subrange(input, 0..case.leaves.len())?;
    let narrowed_range = subrange(input, range.clone())?;
    let left = range.start..narrowed_range.start;
    let right = narrowed_range.end..range.end;
    let leaf_hashes = case.leaf_hashes();
    let expected = case.tree.build_range_proof(narrowed_range.clone());

    // Merkle proofs narrow with leaf hashes, so the range may span several namespaces
    let proof = case.tree.build_range_proof(range.clone());
    let narrowed = proof
        .narrow_range_with_hasher(
            &leaf_hashes[left.clone()],
            &leaf_hashes[right.clone()],
            hasher.clone(),
        )
        .expect("narrowing an honest proof must succeed");
    assert_eq!(narrowed, expected);

    // Namespace proofs hash the extra leaves under a single namespace
    let namespace = case.leaves[range.start].0;
    let extras_in_namespace = case.leaves[left.clone()]
        .iter()
        .chain(&case.leaves[right.clone()])
        .all(|(ns, _)| *ns == namespace);
    let (_, ns_proof) = case.tree.get_range_with_proof(range.clone());
    let narrowed = ns_proof.narrow_range(
        &case.data(left.clone()),
        &case.data(right.clone()),
        namespace,
    );
    if extras_in_namespace {
        let narrowed = narrowed.expect("narrowing an honest namespace proof must succeed");
        assert_eq!(
            narrowed,
            NsProof::PresenceProof {
                proof: expected.clone(),
                ignore_max_ns: case.ignore_max_ns,
            }
        );
        if case.leaves[narrowed_range.clone()]
            .iter()
            .all(|(ns, _)| *ns == namespace)
        {
            assert!(narrowed
                .verify_range(&case.root, &case.data(narrowed_range.clone()), namespace)
                .is_ok());
        }
    } else if let Ok(narrowed) = narrowed {
        // An extra leaf was hashed under the wrong namespace
        assert!(inner(&narrowed)
            .verify_range_with_hasher(
                &case.root,
                &leaf_hashes[narrowed_range.clone()],
                hasher.clone()
            )
            .is_err());
    }

    // Narrowing with a wrong extra leaf must fail, or give a proof which doesn't verify
    let extras = left.len() + right.len();
    if extras > 0 {
        let mut left_hashes = leaf_hashes[left].to_vec();
        let mut right_hashes = leaf_hashes[right].to_vec();
        let index = input.int_in_range(0..=extras - 1)?;
        let target = if index < left_hashes.len() {
            &mut left_hashes[index]
        } else {
            &mut right_hashes[index - left_hashes.len()]
        };
        let original = target.clone();
        *target = if input.arbitrary()? {
            let len = input.int_in_range(0..=32)?;
            hasher.hash_leaf_with_namespace(input.bytes(len)?, namespace)
        } else {
            hasher.hash_leaf_with_namespace(b"", nmt_rs_fuzz::namespace(input)?)
        };
        if *target != original {
            if let Ok(narrowed) =
                proof.narrow_range_with_hasher(&left_hashes, &right_hashes, hasher.clone())
            {
                assert!(narrowed
                    .verify_range_with_hasher(
                        &case.root,
                        &leaf_hashes[narrowed_range],
                        hasher.clone()
                    )
                    .is_err());
            }
        }
    }

    // Absence proofs can't be narrowed
    let mut absence = ns_proof;
    absence.convert_to_absence_proof(leaf_hashes[range.start].clone());
    assert!(absence
        .narrow_range::<Vec<u8>>(&[], &[], namespace)
        .is_err());
    Ok(())
}

/// Narrowing an arbitrary proof may fail, but must not panic.
fn malformed(input: &mut Unstructured<'_>) -> arbitrary::Result<()> {
    let proof = malformed_proof(input)?;
    let left = raw_leaves(input, 40)?;
    let right = raw_leaves(input, 40)?;
    let _ = proof.narrow_range(&left, &right, namespace(input)?);

    let mut left = Vec::new();
    for _ in 0..input.int_in_range(0..=40usize)? {
        left.push(namespaced_hash(input)?);
    }
    let mut right = Vec::new();
    for _ in 0..input.int_in_range(0..=40usize)? {
        right.push(namespaced_hash(input)?);
    }
    let hasher = Hasher::with_ignore_max_ns(input.arbitrary()?);
    let _ = inner(&proof).narrow_range_with_hasher(&left, &right, hasher);
    Ok(())
}

fn check(input: &mut Unstructured<'_>) -> arbitrary::Result<()> {
    if input.arbitrary()? {
        honest(input)
    } else {
        malformed(input)
    }
}

fuzz_target!(|data: &[u8]| {
    let _ = check(&mut Unstructured::new(data));
});
