#![no_main]

use libfuzzer_sys::{arbitrary, arbitrary::Unstructured, fuzz_target};
use nmt_rs::{simple_merkle::proof::Proof, simple_merkle::tree::MerkleHash, NamespacedHash};
use nmt_rs_fuzz::{is_run, namespace, subrange, Hasher, NsProof, TreeCase};

/// Mutates an honest proof, mostly with genuine nodes of the same tree, and requires that whatever
/// still verifies is true.
fn check(input: &mut Unstructured<'_>) -> arbitrary::Result<()> {
    let mut case = TreeCase::arbitrary(input, 24)?;
    let len = case.leaves.len();
    let mut pool = case.nodes();
    pool.push(Hasher::EMPTY_ROOT);

    // Start from an honest proof of a whole namespace, or of an arbitrary range
    let mut query = case.query(input)?;
    let (mut claimed, honest) = if len == 0 || input.arbitrary()? {
        case.tree.get_namespace_with_proof(query)
    } else {
        let range = subrange(input, 0..len)?;
        query = case.leaves[range.start].0;
        case.tree.get_range_with_proof(range)
    };
    let mut siblings = honest.siblings().to_vec();
    let mut range = honest.start_idx()..honest.end_idx();
    let (mut absence, mut ignore_max_ns, mut leaf) = match honest {
        NsProof::AbsenceProof {
            ignore_max_ns,
            leaf,
            ..
        } => (true, ignore_max_ns, leaf),
        NsProof::PresenceProof { ignore_max_ns, .. } => (false, ignore_max_ns, None),
    };

    for _ in 0..input.int_in_range(1..=4u8)? {
        match input.int_in_range(0..=14u8)? {
            0 => range.start = index(input, len)?,
            1 => range.end = index(input, len)?,
            2 => {
                let shift = input.int_in_range(1..=4u32)?;
                if input.arbitrary()? {
                    range = range.start.wrapping_add(shift)..range.end.wrapping_add(shift);
                } else {
                    range = range.start.wrapping_sub(shift)..range.end.wrapping_sub(shift);
                }
            }
            3 => {
                let at = input.int_in_range(0..=siblings.len())?;
                siblings.insert(at, input.choose(&pool)?.clone());
            }
            4 if !siblings.is_empty() => {
                siblings.remove(input.choose_index(siblings.len())?);
            }
            5 if !siblings.is_empty() => {
                let at = input.choose_index(siblings.len())?;
                siblings[at] = input.choose(&pool)?.clone();
            }
            6 if !siblings.is_empty() => {
                let a = input.choose_index(siblings.len())?;
                let b = input.choose_index(siblings.len())?;
                siblings.swap(a, b);
            }
            7 if !siblings.is_empty() => {
                // Keep the hash but claim different namespace bounds
                let at = input.choose_index(siblings.len())?;
                siblings[at] =
                    NamespacedHash::new(namespace(input)?, namespace(input)?, siblings[at].hash());
            }
            8 if len > 0 => {
                // Substitute the genuine proof of another range, optionally with one of its leaves
                let other = subrange(input, 0..len)?;
                siblings = case.tree.build_range_proof(other.clone()).siblings;
                range = other.start as u32..other.end as u32;
                if input.arbitrary()? {
                    leaf = Some(case.leaf_hashes()[other.start].clone());
                }
            }
            9 => {
                leaf = if input.arbitrary()? {
                    Some(input.choose(&pool)?.clone())
                } else {
                    None
                }
            }
            10 => absence = !absence,
            11 => ignore_max_ns = !ignore_max_ns,
            12 => query = case.query(input)?,
            13 if len > 0 => {
                let other = if input.arbitrary()? {
                    subrange(input, 0..len)?
                } else {
                    0..0
                };
                claimed = case.data(other);
            }
            _ => {
                // Edit the claimed leaves
                let replacement = if len > 0 && input.arbitrary()? {
                    input.choose(&case.leaves)?.1.clone()
                } else {
                    let len = input.int_in_range(0..=32)?;
                    input.bytes(len)?.to_vec()
                };
                match input.int_in_range(0..=2u8)? {
                    0 if !claimed.is_empty() => {
                        claimed.remove(input.choose_index(claimed.len())?);
                    }
                    1 if !claimed.is_empty() => {
                        let at = input.choose_index(claimed.len())?;
                        claimed[at] = replacement;
                    }
                    _ => {
                        let at = input.int_in_range(0..=claimed.len())?;
                        claimed.insert(at, replacement);
                    }
                }
            }
        }
    }

    let proof = Proof { siblings, range };
    let forged = if absence {
        NsProof::AbsenceProof {
            proof,
            ignore_max_ns,
            leaf,
        }
    } else {
        NsProof::PresenceProof {
            proof,
            ignore_max_ns,
        }
    };

    if forged
        .verify_complete_namespace(&case.root, &claimed, query)
        .is_ok()
    {
        if case.hides(query) {
            assert!(claimed.is_empty(), "forged max namespace: {forged:?}");
        } else {
            assert_eq!(
                claimed,
                case.data_in(query),
                "forged complete namespace: {forged:?}"
            );
        }
    }
    if forged.verify_range(&case.root, &claimed, query).is_ok() {
        let claimed: Vec<_> = claimed.into_iter().map(|data| (query, data)).collect();
        assert!(is_run(&case.leaves, &claimed), "forged range: {forged:?}");
    }
    Ok(())
}

/// Picks a leaf index near the tree, or anywhere.
fn index(input: &mut Unstructured<'_>, len: usize) -> arbitrary::Result<u32> {
    if input.ratio(1, 8)? {
        input.arbitrary()
    } else {
        input.int_in_range(0..=len as u32 + 1)
    }
}

fuzz_target!(|data: &[u8]| {
    let _ = check(&mut Unstructured::new(data));
});
