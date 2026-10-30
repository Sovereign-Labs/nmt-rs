#![no_main]

use libfuzzer_sys::{arbitrary, arbitrary::Unstructured, fuzz_target};
use nmt_rs::{
    CelestiaNmt, NamespaceId, NamespaceMerkleHasher, NamespacedHash, NamespacedSha2Hasher,
};

fn hash(input: &mut Unstructured<'_>) -> arbitrary::Result<NamespacedHash<29>> {
    Ok(NamespacedHash::new(
        NamespaceId([input.arbitrary()?; 29]),
        NamespaceId([input.arbitrary()?; 29]),
        input.arbitrary()?,
    ))
}

fn check(input: &mut Unstructured<'_>) -> arbitrary::Result<()> {
    let ignore_max_ns: bool = input.arbitrary()?;
    let hasher = || NamespacedSha2Hasher::with_ignore_max_ns(ignore_max_ns);
    let mut namespaces = Vec::new();
    for _ in 0..input.int_in_range(1..=32usize)? {
        let namespace: u8 = input.arbitrary()?;
        namespaces.push(if namespace == u8::MAX {
            namespace
        } else {
            namespace % 16
        });
    }
    namespaces.sort();
    let mut tree = CelestiaNmt::with_hasher(hasher());
    for (i, namespace) in namespaces.iter().enumerate() {
        tree.push_leaf(&i.to_be_bytes(), NamespaceId([*namespace; 29]))
            .unwrap();
    }
    let root = tree.root();
    let hashes: Vec<_> = tree.leaves().iter().map(|l| l.hash().clone()).collect();

    // Narrow a proof of start..end down to new_start..new_end
    let start = input.int_in_range(0..=hashes.len() - 1)?;
    let end = input.int_in_range(start + 1..=hashes.len())?;
    let new_start = input.int_in_range(start..=end - 1)?;
    let new_end = input.int_in_range(new_start + 1..=end)?;
    let mut proof = tree.build_range_proof(start..end);
    let mut left = hashes[start..new_start].to_vec();
    let mut right = hashes[new_end..end].to_vec();

    let tamper: u8 = input.arbitrary()?;
    match tamper % 6 {
        0 => {}
        1 if !proof.siblings.is_empty() => {
            let idx = input.choose_index(proof.siblings.len())?;
            proof.siblings[idx] = hash(input)?;
        }
        2 => {
            let len = input.int_in_range(0..=proof.siblings.len())?;
            proof.siblings.truncate(len);
        }
        3 => proof.siblings.push(hash(input)?),
        // Narrowing takes time linear in the claimed range length, so bound it to keep runs fast
        4 => proof.range = input.int_in_range(0..=1 << 16)?..input.int_in_range(0..=1 << 16)?,
        5 => {
            left = (0..input.int_in_range(0..=8usize)?)
                .map(|_| hash(input))
                .collect::<arbitrary::Result<_>>()?;
            right = (0..input.int_in_range(0..=8usize)?)
                .map(|_| hash(input))
                .collect::<arbitrary::Result<_>>()?;
        }
        _ => return Ok(()),
    }

    let narrowed = proof.narrow_range_with_hasher(&left, &right, hasher());
    if tamper % 6 == 0 {
        let narrowed = narrowed.expect("narrowing a valid proof must succeed");
        assert_eq!(narrowed, tree.build_range_proof(new_start..new_end));
        assert!(narrowed
            .verify_range_with_hasher(&root, &hashes[new_start..new_end], hasher())
            .is_ok());
    }
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    let _ = check(&mut Unstructured::new(data));
});
