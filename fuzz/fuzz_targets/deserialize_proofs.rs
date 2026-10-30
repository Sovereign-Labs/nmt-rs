#![no_main]

use core::fmt::Debug;

use borsh::{BorshDeserialize, BorshSerialize};
use libfuzzer_sys::{arbitrary, arbitrary::Unstructured, fuzz_target};
use nmt_rs::{
    simple_merkle::{db::MemDb, proof::Proof, tree::MerkleTree},
    TmSha2Hasher,
};
use nmt_rs_fuzz::{check_untrusted, subrange, Hash, NsProof, TreeCase};
use serde::{de::DeserializeOwned, Serialize};

type TmProof = Proof<TmSha2Hasher>;

#[derive(Debug, Clone, Copy)]
enum Format {
    Borsh,
    Json,
    /// MessagePack with structs as arrays
    MessagePack,
    /// MessagePack with structs as maps
    MessagePackNamed,
    Postcard,
}

const FORMATS: [Format; 5] = [
    Format::Borsh,
    Format::Json,
    Format::MessagePack,
    Format::MessagePackNamed,
    Format::Postcard,
];

trait Encodable:
    Serialize + DeserializeOwned + BorshSerialize + BorshDeserialize + PartialEq + Debug
{
}

impl<T: Serialize + DeserializeOwned + BorshSerialize + BorshDeserialize + PartialEq + Debug>
    Encodable for T
{
}

fn encode<T: Encodable>(format: Format, value: &T) -> Vec<u8> {
    match format {
        Format::Borsh => borsh::to_vec(value).unwrap(),
        Format::Json => serde_json::to_vec(value).unwrap(),
        Format::MessagePack => rmp_serde::to_vec(value).unwrap(),
        Format::MessagePackNamed => rmp_serde::to_vec_named(value).unwrap(),
        Format::Postcard => postcard::to_stdvec(value).unwrap(),
    }
}

fn decode<T: Encodable>(format: Format, bytes: &[u8]) -> Option<T> {
    match format {
        Format::Borsh => borsh::from_slice(bytes).ok(),
        Format::Json => serde_json::from_slice(bytes).ok(),
        Format::MessagePack | Format::MessagePackNamed => rmp_serde::from_slice(bytes).ok(),
        Format::Postcard => postcard::from_bytes(bytes).ok(),
    }
}

/// Decodes untrusted bytes. Whatever decodes must survive a further round trip unchanged.
fn decode_untrusted<T: Encodable>(format: Format, bytes: &[u8]) -> Option<T> {
    let value = decode::<T>(format, bytes)?;
    assert_eq!(
        decode::<T>(format, &encode(format, &value)).as_ref(),
        Some(&value),
        "{format:?} round trip"
    );
    Some(value)
}

/// Applies a few byte-level edits to an encoding.
fn mutate(input: &mut Unstructured<'_>, bytes: &mut Vec<u8>) -> arbitrary::Result<()> {
    for _ in 0..input.int_in_range(1..=4u8)? {
        let at = input.int_in_range(0..=bytes.len())?;
        match input.int_in_range(0..=3u8)? {
            0 if at < bytes.len() => bytes[at] = input.arbitrary()?,
            1 if at < bytes.len() => {
                bytes.remove(at);
            }
            2 => bytes.truncate(at),
            _ => bytes.insert(at, input.arbitrary()?),
        }
    }
    Ok(())
}

/// Round trips an honest value, then decodes a mutated encoding of it.
fn honest_value<T: Encodable>(
    input: &mut Unstructured<'_>,
    format: Format,
    value: &T,
) -> arbitrary::Result<Option<T>> {
    let mut bytes = encode(format, value);
    assert_eq!(
        decode::<T>(format, &bytes).as_ref(),
        Some(value),
        "{format:?} round trip"
    );
    mutate(input, &mut bytes)?;
    Ok(decode_untrusted(format, &bytes))
}

/// Decodes arbitrary bytes into each type.
fn raw(input: &mut Unstructured<'_>, format: Format) -> arbitrary::Result<()> {
    let len = input.int_in_range(0..=input.len())?;
    let bytes = input.bytes(len)?;
    match input.int_in_range(0..=2u8)? {
        0 => {
            if let Some(proof) = decode_untrusted::<NsProof>(format, bytes) {
                check_untrusted(input, &proof)?;
            }
        }
        1 => {
            if let Some(proof) = decode_untrusted::<TmProof>(format, bytes) {
                let leaves: Vec<[u8; 32]> = input.arbitrary()?;
                let _ = proof.verify_range(&input.arbitrary()?, &leaves);
            }
        }
        _ => {
            let _ = decode_untrusted::<Hash>(format, bytes);
        }
    }
    Ok(())
}

/// Encodes honest proofs and roots, which must round trip and still verify, then decodes mutated
/// encodings of them.
fn honest(input: &mut Unstructured<'_>, format: Format) -> arbitrary::Result<()> {
    let mut case = TreeCase::arbitrary(input, 16)?;
    let namespace = case.query(input)?;
    let (leaves, proof) = case.tree.get_namespace_with_proof(namespace);
    let verified = proof
        .verify_complete_namespace(&case.root, &leaves, namespace)
        .is_ok();
    let decoded: NsProof = decode(format, &encode(format, &proof)).expect("honest proof decodes");
    assert_eq!(
        decoded
            .verify_complete_namespace(&case.root, &leaves, namespace)
            .is_ok(),
        verified
    );
    if let Some(mutated) = honest_value(input, format, &proof)? {
        let _ = mutated.verify_complete_namespace(&case.root, &leaves, namespace);
        check_untrusted(input, &mutated)?;
    }
    if let Some(root) = honest_value(input, format, &case.root)? {
        let _ = proof.verify_complete_namespace(&root, &leaves, namespace);
    }

    // Plain merkle proofs over the same leaves
    let mut tree = MerkleTree::<MemDb<[u8; 32]>, TmSha2Hasher>::new();
    for (_, data) in &case.leaves {
        tree.push_raw_leaf(data);
    }
    let root = tree.root();
    if !case.leaves.is_empty() {
        let range = subrange(input, 0..case.leaves.len())?;
        let leaf_hashes: Vec<_> = tree.leaves()[range.clone()]
            .iter()
            .map(|leaf| *leaf.hash())
            .collect();
        let proof = tree.build_range_proof(range);
        let decoded: TmProof =
            decode(format, &encode(format, &proof)).expect("honest proof decodes");
        assert!(decoded.verify_range(&root, &leaf_hashes).is_ok());
        if let Some(mutated) = honest_value(input, format, &proof)? {
            let _ = mutated.verify_range(&root, &leaf_hashes);
        }
    }
    Ok(())
}

fn check(input: &mut Unstructured<'_>) -> arbitrary::Result<()> {
    let format = *input.choose(&FORMATS)?;
    if input.arbitrary()? {
        honest(input, format)
    } else {
        raw(input, format)
    }
}

fuzz_target!(|data: &[u8]| {
    let _ = check(&mut Unstructured::new(data));
});
