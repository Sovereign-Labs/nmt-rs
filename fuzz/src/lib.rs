//! Input generators and oracles shared by the fuzz targets.

use core::ops::Range;

use libfuzzer_sys::arbitrary::{Result, Unstructured};
use nmt_rs::{
    simple_merkle::{proof::Proof, tree::MerkleHash},
    CelestiaNmt, NamespaceId, NamespaceMerkleHasher, NamespaceProof, NamespacedHash,
    NamespacedSha2Hasher,
};

pub const NS_ID_SIZE: usize = 29;
pub type Namespace = NamespaceId<NS_ID_SIZE>;
pub type Hash = NamespacedHash<NS_ID_SIZE>;
pub type Hasher = NamespacedSha2Hasher<NS_ID_SIZE>;
pub type NsProof = NamespaceProof<Hasher, NS_ID_SIZE>;

/// Generates a namespace in one of several shapes, so that namespace comparisons are decided at
/// different byte positions rather than always at the first one.
pub fn namespace(u: &mut Unstructured<'_>) -> Result<Namespace> {
    let mut id = [0u8; NS_ID_SIZE];
    match u.int_in_range(0..=4u8)? {
        // The same byte everywhere
        0 => id = [u.arbitrary()?; NS_ID_SIZE],
        // A shared prefix with a short arbitrary suffix, like Celestia user namespaces
        1 => {
            id = [u.arbitrary()?; NS_ID_SIZE];
            let suffix = u.int_in_range(1..=4usize)?;
            u.fill_buffer(&mut id[NS_ID_SIZE - suffix..])?;
        }
        // A single arbitrary byte at an arbitrary position
        2 => id[u.choose_index(NS_ID_SIZE)?] = u.arbitrary()?,
        // Boundary values around the reserved and maximum namespaces
        3 => {
            let mut below_max = Namespace::MAX_ID.0;
            below_max[NS_ID_SIZE - 1] = 0xfe;
            id = *u.choose(&[
                [0; NS_ID_SIZE],
                Namespace::MAX_RESERVED_ID_ON_CELESTIA.0,
                below_max,
                Namespace::MAX_ID.0,
                Namespace::MAX_ID.0,
            ])?;
        }
        _ => u.fill_buffer(&mut id)?,
    }
    Ok(NamespaceId(id))
}

/// Generates a namespaced hash with arbitrary, possibly inverted, namespace bounds.
pub fn namespaced_hash(u: &mut Unstructured<'_>) -> Result<Hash> {
    Ok(NamespacedHash::new(
        namespace(u)?,
        namespace(u)?,
        u.arbitrary()?,
    ))
}

/// Generates a proof that need not correspond to any tree.
pub fn malformed_proof(u: &mut Unstructured<'_>) -> Result<NsProof> {
    let start: u32 = if u.arbitrary()? {
        u.arbitrary()?
    } else {
        u.int_in_range(0..=64)?
    };
    let end = if u.arbitrary()? {
        start.wrapping_add(u.int_in_range(0..=40)?)
    } else {
        u.arbitrary()?
    };
    let mut siblings = Vec::new();
    for _ in 0..u.int_in_range(0..=32usize)? {
        siblings.push(namespaced_hash(u)?);
    }
    let proof = Proof {
        siblings,
        range: start..end,
    };
    let ignore_max_ns = u.arbitrary()?;
    Ok(if u.arbitrary()? {
        NsProof::AbsenceProof {
            proof,
            ignore_max_ns,
            leaf: if u.arbitrary()? {
                Some(namespaced_hash(u)?)
            } else {
                None
            },
        }
    } else {
        NsProof::PresenceProof {
            proof,
            ignore_max_ns,
        }
    })
}

/// Generates up to `max` raw leaves of up to 64 bytes each.
pub fn raw_leaves(u: &mut Unstructured<'_>, max: usize) -> Result<Vec<Vec<u8>>> {
    let mut leaves = Vec::new();
    for _ in 0..u.int_in_range(0..=max)? {
        let len = u.int_in_range(0..=64usize)?;
        leaves.push(u.bytes(len)?.to_vec());
    }
    Ok(leaves)
}

/// Feeds an untrusted proof to every verifier and to narrowing. Any of them may reject it, but none
/// may panic.
pub fn check_untrusted(u: &mut Unstructured<'_>, proof: &NsProof) -> Result<()> {
    let root = if u.ratio(1, 8)? {
        Hasher::EMPTY_ROOT
    } else {
        namespaced_hash(u)?
    };
    let leaves = raw_leaves(u, 16)?;
    let namespace = namespace(u)?;
    let hasher = Hasher::with_ignore_max_ns(u.arbitrary()?);
    let _ = proof.verify_complete_namespace(&root, &leaves, namespace);
    let _ = proof.verify_range(&root, &leaves, namespace);
    let _ = proof.verify_complete_namespace_with_hasher(&root, &leaves, namespace, hasher.clone());
    let _ = proof.verify_range_with_hasher(&root, &leaves, namespace, hasher);
    let split = u.int_in_range(0..=leaves.len())?;
    let _ = proof.narrow_range(&leaves[..split], &leaves[split..], namespace);
    Ok(())
}

/// Returns the merkle proof wrapped by a namespace proof.
pub fn inner(proof: &NsProof) -> &Proof<Hasher> {
    match proof {
        NsProof::AbsenceProof { proof, .. } | NsProof::PresenceProof { proof, .. } => proof,
    }
}

/// Picks a nonempty subrange of `range`, which must itself be nonempty.
pub fn subrange(u: &mut Unstructured<'_>, range: Range<usize>) -> Result<Range<usize>> {
    let start = u.int_in_range(range.start..=range.end - 1)?;
    let end = u.int_in_range(start + 1..=range.end)?;
    Ok(start..end)
}

/// Returns whether `needle` occurs as a contiguous run of `haystack`. Range proofs don't
/// authenticate their start index (in this crate or in celestiaorg/nmt), so a valid proof shows
/// only that its leaves occur contiguously somewhere in the tree.
pub fn is_run<T: PartialEq>(haystack: &[T], needle: &[T]) -> bool {
    needle.is_empty()
        || haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// Appends every node of the tree over `leaves` to `out`, from the leaves up to the root.
pub fn collect_nodes<M: MerkleHash>(hasher: &M, leaves: &[M::Output], out: &mut Vec<M::Output>) {
    fn subtree<M: MerkleHash>(
        hasher: &M,
        leaves: &[M::Output],
        out: &mut Vec<M::Output>,
    ) -> M::Output {
        let node = if leaves.len() == 1 {
            leaves[0].clone()
        } else {
            let split = leaves.len().next_power_of_two() / 2;
            let left = subtree(hasher, &leaves[..split], out);
            let right = subtree(hasher, &leaves[split..], out);
            hasher.hash_nodes(&left, &right)
        };
        out.push(node.clone());
        node
    }
    if !leaves.is_empty() {
        subtree(hasher, leaves, out);
    }
}

/// An honestly built namespaced merkle tree together with the leaves it was built from.
pub struct TreeCase {
    pub tree: CelestiaNmt,
    pub root: Hash,
    pub ignore_max_ns: bool,
    /// The leaves in tree order, sorted by namespace
    pub leaves: Vec<(Namespace, Vec<u8>)>,
    /// The namespaces leaves were drawn from. Some may be unused.
    pub palette: Vec<Namespace>,
}

impl TreeCase {
    /// Builds a tree of up to `max_leaves` leaves. Leaves draw their namespaces from a small
    /// palette, so namespaces usually hold several leaves.
    pub fn arbitrary(u: &mut Unstructured<'_>, max_leaves: usize) -> Result<Self> {
        let ignore_max_ns = u.arbitrary()?;
        let mut palette = Vec::new();
        for _ in 0..u.int_in_range(1..=6usize)? {
            palette.push(namespace(u)?);
        }
        let mut leaves = Vec::new();
        for _ in 0..u.int_in_range(0..=max_leaves)? {
            let namespace = *u.choose(&palette)?;
            let len = u.int_in_range(0..=32usize)?;
            leaves.push((namespace, u.bytes(len)?.to_vec()));
        }
        leaves.sort_by_key(|(namespace, _)| *namespace);
        let mut tree = CelestiaNmt::with_hasher(Hasher::with_ignore_max_ns(ignore_max_ns));
        for (namespace, data) in &leaves {
            tree.push_leaf(data, *namespace).unwrap();
        }
        let root = tree.root();
        Ok(Self {
            tree,
            root,
            ignore_max_ns,
            leaves,
            palette,
        })
    }

    pub fn hasher(&self) -> Hasher {
        Hasher::with_ignore_max_ns(self.ignore_max_ns)
    }

    /// Picks a namespace from the palette, or a fresh one which is most likely absent.
    pub fn query(&self, u: &mut Unstructured<'_>) -> Result<Namespace> {
        if u.arbitrary()? {
            Ok(*u.choose(&self.palette)?)
        } else {
            namespace(u)
        }
    }

    /// Returns the indices of the leaves in `namespace`.
    pub fn range_of(&self, namespace: Namespace) -> Range<usize> {
        self.leaves.partition_point(|(ns, _)| *ns < namespace)
            ..self.leaves.partition_point(|(ns, _)| *ns <= namespace)
    }

    /// Returns the data of the leaves in `range`.
    pub fn data(&self, range: Range<usize>) -> Vec<Vec<u8>> {
        self.leaves[range]
            .iter()
            .map(|(_, data)| data.clone())
            .collect()
    }

    /// Returns the data of the leaves in `namespace`.
    pub fn data_in(&self, namespace: Namespace) -> Vec<Vec<u8>> {
        self.data(self.range_of(namespace))
    }

    /// Whether `namespace` is the max namespace and lies outside the root's namespace range. Such
    /// a namespace can only be proven absent, with an empty proof, even if the tree has leaves in it.
    pub fn hides(&self, namespace: Namespace) -> bool {
        self.ignore_max_ns
            && namespace == Namespace::MAX_ID
            && self.leaves.iter().any(|(ns, _)| *ns != namespace)
    }

    pub fn leaf_hashes(&self) -> Vec<Hash> {
        self.tree
            .leaves()
            .iter()
            .map(|leaf| leaf.hash().clone())
            .collect()
    }

    /// Returns every node of the tree, from the leaves up to the root.
    pub fn nodes(&self) -> Vec<Hash> {
        let mut nodes = Vec::new();
        collect_nodes(&self.hasher(), &self.leaf_hashes(), &mut nodes);
        nodes
    }
}
