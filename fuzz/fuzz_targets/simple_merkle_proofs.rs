#![no_main]

use libfuzzer_sys::{arbitrary, arbitrary::Unstructured, fuzz_target};
use nmt_rs::{
    simple_merkle::{
        db::MemDb,
        proof::Proof,
        tree::{MerkleHash, MerkleTree},
    },
    TmSha2Hasher,
};
use nmt_rs_fuzz::{collect_nodes, is_run, raw_leaves, subrange};
use sha2::Sha256;
use tendermint::merkle::simple_hash_from_byte_vectors;

type TmTree = MerkleTree<MemDb<[u8; 32]>, TmSha2Hasher>;
type TmProof = Proof<TmSha2Hasher>;

fn leaf_hash(data: &[u8]) -> [u8; 32] {
    TmSha2Hasher::new().hash_leaf(data)
}

fn honest(input: &mut Unstructured<'_>) -> arbitrary::Result<()> {
    let leaves = raw_leaves(input, 64)?;
    let mut tree = TmTree::new();
    for leaf in &leaves {
        tree.push_raw_leaf(leaf);
    }
    let root = tree.root();
    assert_eq!(root, simple_hash_from_byte_vectors::<Sha256>(&leaves));
    if leaves.is_empty() {
        return Ok(());
    }
    let leaf_hashes: Vec<_> = tree.leaves().iter().map(|leaf| *leaf.hash()).collect();

    // Ranges and single leaves
    let range = subrange(input, 0..leaves.len())?;
    let (data, proof) = tree.get_range_with_proof(range.clone());
    assert_eq!(data, leaves[range.clone()]);
    assert!(proof
        .verify_range(&root, &leaf_hashes[range.clone()])
        .is_ok());
    assert!(proof
        .verify_range_with_hasher(&root, &leaf_hashes[range.clone()], TmSha2Hasher::new())
        .is_ok());
    let index = input.int_in_range(range.start..=range.end - 1)?;
    let (data, single) = tree.get_index_with_proof(index);
    assert_eq!(data, leaves[index]);
    assert!(single
        .verify_range(&root, &leaf_hashes[index..index + 1])
        .is_ok());

    // Narrowing gives the proof the tree builds for the narrower range
    let narrowed_range = subrange(input, range.clone())?;
    let mut left = leaf_hashes[range.start..narrowed_range.start].to_vec();
    let mut right = leaf_hashes[narrowed_range.end..range.end].to_vec();
    let narrowed = proof
        .narrow_range_with_hasher(&left, &right, TmSha2Hasher::new())
        .expect("narrowing an honest proof must succeed");
    assert_eq!(narrowed, tree.build_range_proof(narrowed_range.clone()));

    // Narrowing with a wrong extra leaf gives a proof which doesn't verify
    let extras = left.len() + right.len();
    if extras > 0 {
        let at = input.int_in_range(0..=extras - 1)?;
        let target = if at < left.len() {
            &mut left[at]
        } else {
            &mut right[at - left.len()]
        };
        let original = *target;
        let len = input.int_in_range(0..=32)?;
        *target = leaf_hash(input.bytes(len)?);
        if *target != original {
            if let Ok(narrowed) = proof.narrow_range_with_hasher(&left, &right, TmSha2Hasher::new())
            {
                assert!(narrowed
                    .verify_range(&root, &leaf_hashes[narrowed_range])
                    .is_err());
            }
        }
    }

    // Forged proofs: whatever still verifies must be a contiguous run of leaves
    let mut pool = Vec::new();
    collect_nodes(&TmSha2Hasher::new(), &leaf_hashes, &mut pool);
    let TmProof {
        mut siblings,
        range: mut forged_range,
    } = proof;
    let mut claimed = leaves[range].to_vec();
    let len = leaves.len();
    for _ in 0..input.int_in_range(1..=4u8)? {
        match input.int_in_range(0..=9u8)? {
            0 => forged_range.start = input.int_in_range(0..=len as u32 + 1)?,
            1 => forged_range.end = input.int_in_range(0..=len as u32 + 1)?,
            2 => {
                let shift = input.int_in_range(1..=4u32)?;
                forged_range =
                    forged_range.start.wrapping_sub(shift)..forged_range.end.wrapping_sub(shift);
            }
            3 => {
                let at = input.int_in_range(0..=siblings.len())?;
                siblings.insert(at, *input.choose(&pool)?);
            }
            4 if !siblings.is_empty() => {
                siblings.remove(input.choose_index(siblings.len())?);
            }
            5 if !siblings.is_empty() => {
                let at = input.choose_index(siblings.len())?;
                siblings[at] = *input.choose(&pool)?;
            }
            6 if !siblings.is_empty() => {
                let a = input.choose_index(siblings.len())?;
                let b = input.choose_index(siblings.len())?;
                siblings.swap(a, b);
            }
            7 => {
                let other = subrange(input, 0..len)?;
                siblings = tree.build_range_proof(other.clone()).siblings;
                forged_range = other.start as u32..other.end as u32;
            }
            8 => claimed = leaves[subrange(input, 0..len)?].to_vec(),
            _ => {
                let replacement = if input.arbitrary()? {
                    input.choose(&leaves)?.clone()
                } else {
                    let len = input.int_in_range(0..=32)?;
                    input.bytes(len)?.to_vec()
                };
                if !claimed.is_empty() && input.arbitrary()? {
                    let at = input.choose_index(claimed.len())?;
                    claimed[at] = replacement;
                } else {
                    claimed.push(replacement);
                }
            }
        }
    }
    let forged = TmProof {
        siblings,
        range: forged_range,
    };
    let claimed_hashes: Vec<_> = claimed.iter().map(|data| leaf_hash(data)).collect();
    if forged.verify_range(&root, &claimed_hashes).is_ok() {
        assert!(is_run(&leaves, &claimed), "forged range: {forged:?}");
    }
    Ok(())
}

/// Verifying or narrowing an arbitrary proof may fail, but must not panic.
fn malformed(input: &mut Unstructured<'_>) -> arbitrary::Result<()> {
    let root = if input.ratio(1, 8)? {
        TmSha2Hasher::EMPTY_ROOT
    } else {
        input.arbitrary()?
    };
    let start: u32 = if input.arbitrary()? {
        input.arbitrary()?
    } else {
        input.int_in_range(0..=64)?
    };
    let end = if input.arbitrary()? {
        start.wrapping_add(input.int_in_range(0..=40)?)
    } else {
        input.arbitrary()?
    };
    let siblings = (0..input.int_in_range(0..=32usize)?)
        .map(|_| input.arbitrary())
        .collect::<arbitrary::Result<_>>()?;
    let proof = TmProof {
        siblings,
        range: start..end,
    };
    let hashes = |input: &mut Unstructured<'_>| {
        (0..input.int_in_range(0..=40usize)?)
            .map(|_| input.arbitrary())
            .collect::<arbitrary::Result<Vec<[u8; 32]>>>()
    };
    let leaves = hashes(input)?;
    let _ = proof.verify_range(&root, &leaves);
    let left = hashes(input)?;
    let right = hashes(input)?;
    let _ = proof.narrow_range_with_hasher(&left, &right, TmSha2Hasher::new());
    Ok(())
}

fn check(input: &mut Unstructured<'_>) -> arbitrary::Result<()> {
    if input.ratio(1, 4)? {
        malformed(input)
    } else {
        honest(input)
    }
}

fuzz_target!(|data: &[u8]| {
    let _ = check(&mut Unstructured::new(data));
});
