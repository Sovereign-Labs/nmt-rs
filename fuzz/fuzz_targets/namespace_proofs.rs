#![no_main]

use libfuzzer_sys::{arbitrary, arbitrary::Unstructured, fuzz_target};
use nmt_rs::{CelestiaNmt, NamespaceId, NamespaceMerkleHasher, NamespacedSha2Hasher};

fn check(input: &mut Unstructured<'_>) -> arbitrary::Result<()> {
    let ignore_max_ns = input.arbitrary()?;
    let choose_present: bool = input.arbitrary()?;
    let query: u8 = input.arbitrary()?;
    let from: u8 = input.arbitrary()?;
    let to: u8 = input.arbitrary()?;
    let tamper: bool = input.arbitrary()?;
    let mut leaves = Vec::new();
    for _ in 0..input.int_in_range(0..=32usize)? {
        let namespace: u8 = input.arbitrary()?;
        let namespace = if namespace == u8::MAX {
            namespace
        } else {
            namespace % 16
        };
        let len = input.int_in_range(0..=64usize)?;
        leaves.push((namespace, input.bytes(len)?.to_vec()));
    }
    leaves.sort_by_key(|(namespace, _)| *namespace);
    let mut tree =
        CelestiaNmt::with_hasher(NamespacedSha2Hasher::with_ignore_max_ns(ignore_max_ns));
    for (namespace, data) in &leaves {
        tree.push_leaf(data, NamespaceId([*namespace; 29])).unwrap();
    }
    let root = tree.root();
    let mut query = if choose_present && !leaves.is_empty() {
        leaves[query as usize % leaves.len()].0
    } else {
        query
    };
    // The maximum namespace is excluded from namespace queries in this mode.
    if ignore_max_ns && query == u8::MAX {
        query -= 1;
    }
    let namespace = NamespaceId([query; 29]);
    let expected: Vec<_> = leaves
        .iter()
        .filter(|(ns, _)| *ns == query)
        .map(|(_, data)| data.clone())
        .collect();
    let (actual, proof) = tree.get_namespace_with_proof(namespace);
    assert_eq!(actual, expected);
    assert!(proof
        .verify_complete_namespace(&root, &expected, namespace)
        .is_ok());

    if !expected.is_empty() {
        let start = from as usize % expected.len();
        let end = start + 1 + to as usize % (expected.len() - start);
        let offset = leaves.partition_point(|(ns, _)| *ns < query);
        let (actual, partial) = tree.get_range_with_proof(offset + start..offset + end);
        assert_eq!(actual, expected[start..end]);
        assert!(partial.verify_range(&root, &actual, namespace).is_ok());
        assert_eq!(
            partial
                .verify_complete_namespace(&root, &actual, namespace)
                .is_ok(),
            start == 0 && end == expected.len()
        );
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
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    let _ = check(&mut Unstructured::new(data));
});
