//! Implements a simple [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962#section-2.1) compatible merkle tree
//! over an in-memory data store which maps preimages to hashes.
pub mod db;
pub mod error;
pub mod proof;
pub mod tree;
pub mod utils;
