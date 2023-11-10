//! Implements a simple [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962#section-2.1) compatible merkle tree
//! over an in-memory data store which maps preimages to hashes.

/// Defines traits and types for storing hashes and preimages.
pub mod db;
/// Defines errors that might arise in proof verification.
pub mod error;
/// Defines proofs on the tree.
pub mod proof;
/// Defines the merkle tree itself.
pub mod tree;
/// Utilities for computing facts about trees from proofs.
pub mod utils;
