#![no_main]

use libfuzzer_sys::{arbitrary, arbitrary::Unstructured, fuzz_target};
use nmt_rs::{
    simple_merkle::proof::Proof, NamespaceId, NamespaceProof, NamespacedHash, NamespacedSha2Hasher,
};

fn hash(input: &mut Unstructured<'_>) -> arbitrary::Result<NamespacedHash<29>> {
    Ok(NamespacedHash::new(
        NamespaceId([input.arbitrary()?; 29]),
        NamespaceId([input.arbitrary()?; 29]),
        input.arbitrary()?,
    ))
}

fn check(input: &mut Unstructured<'_>) -> arbitrary::Result<()> {
    let complete: bool = input.arbitrary()?;
    let absence: bool = input.arbitrary()?;
    let ignore_max_ns = input.arbitrary()?;
    let namespace = NamespaceId([input.arbitrary()?; 29]);
    let start: u32 = input.arbitrary()?;
    let root = hash(input)?;
    let leaf = if input.arbitrary()? {
        Some(hash(input)?)
    } else {
        None
    };
    let mut leaves = Vec::new();
    for _ in 0..input.int_in_range(0..=16usize)? {
        let len = input.int_in_range(0..=64usize)?;
        leaves.push(input.bytes(len)?.to_vec());
    }
    let end = if input.arbitrary()? {
        start.wrapping_add(leaves.len() as u32)
    } else {
        input.arbitrary()?
    };
    let mut siblings = Vec::new();
    for _ in 0..input.int_in_range(0..=32usize)? {
        siblings.push(hash(input)?);
    }
    let proof = Proof::<NamespacedSha2Hasher<29>> {
        siblings,
        range: start..end,
    };
    let proof = if absence {
        NamespaceProof::AbsenceProof {
            proof,
            ignore_max_ns,
            leaf,
        }
    } else {
        NamespaceProof::PresenceProof {
            proof,
            ignore_max_ns,
        }
    };
    if complete {
        let _ = proof.verify_complete_namespace(&root, &leaves, namespace);
    } else {
        let _ = proof.verify_range(&root, &leaves, namespace);
    }
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    let _ = check(&mut Unstructured::new(data));
});
