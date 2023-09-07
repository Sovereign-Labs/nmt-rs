#[derive(Debug, PartialEq, Clone, Copy)]
pub enum RangeProofError {
    NoLeavesProvided,
    WrongAmountOfLeavesProvided,
    InvalidRoot,
    MissingLeaf,
    MissingProofNode,
    TreeDoesNotContainLeaf,
    TreeIsEmpty,
    TreeTooLarge,
    /// Indicates that the tree is not properly ordered by namespace
    MalformedTree,
    MalformedProof,
}
