/// An error that occurred while trying to check a claimed range proof for a merkle tree.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum RangeProofError {
    /// The tree is not empty, but no leaves were provided. This proof is malformed - even proofs of absence must provide a leaf.
    NoLeavesProvided,
    /// The proof is malformed - the number of leaves provided does not match the claimed size of the range
    WrongAmountOfLeavesProvided,
    /// The claimed proof does not verify against the provided root
    InvalidRoot,
    /// The claimed range was invalid because it left out a leaf
    MissingLeaf,
    /// The proof is missing a node that was needed for verification
    MissingProofNode,
    /// A claimed leaf was not actually present in the tree
    TreeDoesNotContainLeaf,
    /// The claimed tree exceeds the maximum allowed size (currently 2^32 leaves)
    TreeTooLarge,
    /// Indicates that the tree is not properly ordered by namespace
    MalformedTree,
    /// A catch all error which indicates that the proof is malformed
    MalformedProof(&'static str),
}
