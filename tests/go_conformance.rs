//! Known-answer tests against vectors produced by the Go reference implementation.
//! See `tests/fixtures/go/README.md` for their provenance.

use std::panic::{catch_unwind, AssertUnwindSafe};

use nmt_rs::{
    simple_merkle::{db::MemDb, proof::Proof, tree::MerkleHash},
    CelestiaNmt, NamespaceId, NamespaceMerkleHasher, NamespaceMerkleTree, NamespaceProof,
    NamespacedHash, NamespacedSha2Hasher,
};
use serde_json::Value;

const NS: usize = 8;
type Hasher = NamespacedSha2Hasher<NS>;
type Tree = NamespaceMerkleTree<MemDb<NamespacedHash<NS>>, Hasher, NS>;

fn fixture(name: &str) -> Value {
    let path = format!("{}/tests/fixtures/go/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn bytes(hex: &Value) -> Vec<u8> {
    let hex = hex.as_str().unwrap();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn list<T>(values: &Value, f: impl Fn(&Value) -> T) -> Vec<T> {
    values.as_array().unwrap().iter().map(f).collect()
}

fn node<const N: usize>(hex: &Value) -> NamespacedHash<N> {
    NamespacedHash::try_from(bytes(hex).as_slice()).unwrap()
}

fn namespace(hex: &Value) -> NamespaceId<NS> {
    NamespaceId::try_from(bytes(hex).as_slice()).unwrap()
}

/// Splits a Go raw leaf (`namespace || data`) into its parts
fn split_leaf(leaf: &[u8]) -> (NamespaceId<NS>, &[u8]) {
    (leaf[..NS].try_into().unwrap(), &leaf[NS..])
}

fn tree(leaves: &Value, ignore_max_ns: bool) -> Tree {
    let mut tree = Tree::with_hasher(Hasher::with_ignore_max_ns(ignore_max_ns));
    for leaf in list(leaves, bytes) {
        let (namespace, data) = split_leaf(&leaf);
        tree.push_leaf(data, namespace).unwrap();
    }
    tree
}

fn go_proof(proof: &Value) -> NamespaceProof<Hasher, NS> {
    let proof_range = Proof {
        siblings: list(&proof["nodes_hex"], node),
        range: proof["start"].as_u64().unwrap() as u32..proof["end"].as_u64().unwrap() as u32,
    };
    let ignore_max_ns = proof["is_max_namespace_ignored"].as_bool().unwrap();
    // Go encodes an empty proof as an inclusion proof of the empty range
    if proof.get("leaf_hash_hex").is_some() || proof_range.range.is_empty() {
        NamespaceProof::AbsenceProof {
            proof: proof_range,
            ignore_max_ns,
            leaf: proof.get("leaf_hash_hex").map(node),
        }
    } else {
        NamespaceProof::PresenceProof {
            proof: proof_range,
            ignore_max_ns,
        }
    }
}

#[test]
fn go_hashes() {
    let fixture = fixture("hashes.json");
    assert_eq!(Hasher::EMPTY_ROOT, node(&fixture["empty_root_hex"]));

    for case in fixture["leaf_cases"].as_array().unwrap() {
        let leaf = bytes(&case["leaf_hex"]);
        let (namespace, data) = split_leaf(&leaf);
        let expected = node(&case["hash_hex"]);
        for ignore_max_ns in [true, false] {
            let hasher = Hasher::with_ignore_max_ns(ignore_max_ns);
            assert_eq!(hasher.hash_leaf(&leaf), expected, "{}", case["label"]);
            assert_eq!(
                hasher.hash_leaf_with_namespace(data, namespace),
                expected,
                "{}",
                case["label"]
            );
        }
    }

    for case in fixture["node_cases"].as_array().unwrap() {
        let hasher = Hasher::with_ignore_max_ns(case["ignore_max_namespace"].as_bool().unwrap());
        let parent = hasher.hash_nodes(&node(&case["left_hex"]), &node(&case["right_hex"]));
        assert_eq!(parent, node(&case["hash_hex"]), "{}", case["label"]);
    }

    for case in fixture["parse_cases"].as_array().unwrap() {
        let parsed = NamespacedHash::<NS>::try_from(bytes(&case["node_hex"]).as_slice());
        match case["label"].as_str().unwrap() {
            // Covered by `go_rejects_hash_with_min_namespace_above_max`
            "invalid-namespace-order" => {}
            label => assert_eq!(parsed.is_ok(), case["valid"].as_bool().unwrap(), "{label}"),
        }
    }
}

#[test]
fn go_roots() {
    for case in fixture("roots.json")["cases"].as_array().unwrap() {
        let ignore_max_ns = case["ignore_max_namespace"].as_bool().unwrap();
        let root = tree(&case["leaves_hex"], ignore_max_ns).root();
        assert_eq!(root, node(&case["root_hex"]), "{}", case["label"]);
    }
}

#[test]
fn go_proofs() {
    for case in fixture("proofs.json")["cases"].as_array().unwrap() {
        let mut tree = tree(&case["leaves_hex"], true);
        let root = tree.root();
        assert_eq!(root, node(&case["root_hex"]), "{}", case["label"]);

        for ns_case in case["namespace_cases"].as_array().unwrap() {
            let label = &ns_case["label"];
            let namespace = namespace(&ns_case["namespace_hex"]);
            let expected_leaves: Vec<Vec<u8>> = list(&ns_case["leaves_hex"], |leaf| {
                split_leaf(&bytes(leaf)).1.to_vec()
            });
            let expected_proof = go_proof(&ns_case["proof"]);

            let (leaves, proof) = tree.get_namespace_with_proof(namespace);
            assert_eq!(leaves, expected_leaves, "{label}");
            assert_eq!(proof, expected_proof, "{label}");
            assert!(
                expected_proof
                    .verify_complete_namespace(&root, &expected_leaves, namespace)
                    .is_ok(),
                "{label}"
            );
        }

        for range_case in case["range_cases"].as_array().unwrap() {
            let label = &range_case["label"];
            let start = range_case["start"].as_u64().unwrap() as usize;
            let end = range_case["end"].as_u64().unwrap() as usize;
            let leaf_hashes = list(&range_case["leaf_hashes_hex"], node);
            let NamespaceProof::PresenceProof {
                proof: expected_proof,
                ..
            } = go_proof(&range_case["proof"])
            else {
                panic!("{label}: expected an inclusion proof");
            };

            let actual_hashes: Vec<_> = tree.leaves()[start..end]
                .iter()
                .map(|leaf| leaf.hash().clone())
                .collect();
            assert_eq!(actual_hashes, leaf_hashes, "{label}");
            assert_eq!(
                tree.build_range_proof(start..end),
                expected_proof,
                "{label}"
            );
            assert!(
                expected_proof
                    .verify_range_with_hasher(&root, &leaf_hashes, Hasher::with_ignore_max_ns(true))
                    .is_ok(),
                "{label}"
            );
        }
    }
}

#[test]
fn go_malformed() {
    for case in fixture("malformed.json")["cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        match label {
            "invalid-namespace-length" => {
                assert!(
                    NamespaceId::<NS>::try_from(bytes(&case["namespace_hex"]).as_slice()).is_err()
                )
            }
            "invalid-node-length" => {
                assert!(
                    NamespacedHash::<NS>::try_from(bytes(&case["node_hex"]).as_slice()).is_err()
                )
            }
            "unordered-leaves" => {
                let mut tree = Tree::with_hasher(Hasher::with_ignore_max_ns(true));
                let results: Vec<_> = list(&case["leaves_hex"], bytes)
                    .iter()
                    .map(|leaf| {
                        let (namespace, data) = split_leaf(leaf);
                        tree.push_leaf(data, namespace)
                    })
                    .collect();
                assert!(results.iter().any(Result::is_err), "{label}");
            }
            "unordered-siblings" => {
                let hasher = Hasher::with_ignore_max_ns(true);
                assert!(hasher
                    .try_hash_nodes(&node(&case["left_hex"]), &node(&case["right_hex"]))
                    .is_err());
            }
            // Go refuses to build the proof; nmt-rs builds one which must not verify
            "invalid-range-empty" => {
                let mut tree = tree(&case["leaves_hex"], true);
                let root = tree.root();
                let proof = tree.build_range_proof(0..0);
                assert!(proof
                    .verify_range_with_hasher(&root, &[], Hasher::with_ignore_max_ns(true))
                    .is_err());
            }
            // Go returns an error; nmt-rs documents a panic
            "invalid-range-past-end" => {
                let end = case["end"].as_u64().unwrap() as usize;
                let mut tree = tree(&case["leaves_hex"], true);
                assert!(catch_unwind(AssertUnwindSafe(|| tree.build_range_proof(0..end))).is_err());
            }
            // Covered by the ignored `go_rejects_*` tests below
            "invalid-leaf-length" | "invalid-node-namespace-order" => {}
            // nmt-rs has no subroot paths API
            "invalid-subroot-path" => {}
            _ => panic!("unhandled case {label}"),
        }
    }
}

// TODO: Go rejects namespaced hashes whose min namespace exceeds the max namespace, nmt-rs accepts them
#[test]
#[ignore = "nmt-rs diverges from Go: NamespacedHash::try_from doesn't check namespace order"]
fn go_rejects_hash_with_min_namespace_above_max() {
    for (file, cases, label) in [
        ("hashes.json", "parse_cases", "invalid-namespace-order"),
        ("malformed.json", "cases", "invalid-node-namespace-order"),
    ] {
        let fixture = fixture(file);
        let case = fixture[cases]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["label"] == label)
            .unwrap();
        assert!(
            NamespacedHash::<NS>::try_from(bytes(&case["node_hex"]).as_slice()).is_err(),
            "{label}"
        );
    }
}

// TODO: Go returns an error for leaves shorter than the namespace, nmt-rs panics
#[test]
#[ignore = "nmt-rs diverges from Go: MerkleHash::hash_leaf panics on leaves shorter than the namespace"]
fn go_rejects_leaf_shorter_than_namespace() {
    let fixture = fixture("malformed.json");
    let case = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["label"] == "invalid-leaf-length")
        .unwrap();
    let leaf = bytes(&case["leaf_hex"]);
    assert!(catch_unwind(|| Hasher::with_ignore_max_ns(true).hash_leaf(&leaf)).is_ok());
}

/// Builds the row and column roots of an extended data square like Go's `ErasuredNamespacedMerkleTree`:
/// shares in the original quadrant are namespaced by their prefix, all others by the parity namespace.
#[test]
fn go_erasured_row_and_column_roots() {
    const CELESTIA_NS: usize = 29;
    let parity = NamespaceId([0xff; CELESTIA_NS]);

    for case in fixture("erasure.json")["cases"].as_array().unwrap() {
        let label = &case["label"];
        let width = case["width"].as_u64().unwrap() as usize;
        let shares = list(&case["extended_shares_hex"], bytes);
        let axis_root = |share_at: &dyn Fn(usize) -> (usize, usize)| {
            let mut tree = CelestiaNmt::with_hasher(NamespacedSha2Hasher::with_ignore_max_ns(true));
            for i in 0..width {
                let (row, col) = share_at(i);
                let share = &shares[row * width + col];
                let namespace = if row < width / 2 && col < width / 2 {
                    share[..CELESTIA_NS].try_into().unwrap()
                } else {
                    parity
                };
                tree.push_leaf(share, namespace).unwrap();
            }
            tree.root()
        };

        let row_roots: Vec<_> = (0..width).map(|row| axis_root(&|col| (row, col))).collect();
        let col_roots: Vec<_> = (0..width).map(|col| axis_root(&|row| (row, col))).collect();
        assert_eq!(row_roots, list(&case["row_roots_hex"], node), "{label}");
        assert_eq!(col_roots, list(&case["column_roots_hex"], node), "{label}");
    }
}

/// Row proofs from `ShareProof`s served by celestia-app for real transactions and shares
#[test]
fn go_share_proofs() {
    for row in fixture("share_proofs.json")["rows"].as_array().unwrap() {
        let namespace =
            NamespaceId::<29>::try_from(bytes(&row["namespace_hex"]).as_slice()).unwrap();
        let proof = NamespaceProof::<NamespacedSha2Hasher<29>, 29>::PresenceProof {
            proof: Proof {
                siblings: list(&row["nodes_hex"], node),
                range: row["start"].as_u64().unwrap() as u32..row["end"].as_u64().unwrap() as u32,
            },
            ignore_max_ns: true,
        };
        let shares = list(&row["shares_hex"], bytes);
        assert!(
            proof
                .verify_range(&node(&row["row_root_hex"]), &shares, namespace)
                .is_ok(),
            "{}",
            row["source"]
        );
    }
}
