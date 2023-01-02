use super::error::RangeProofError;

/// Compute the number of left siblings required for an inclusion proof of the node at the provided index
pub fn compute_num_left_siblings(node_idx: usize) -> usize {
    // The number of left siblings needed is the same as the number of ones in the binary
    // decomposition of the start index
    let mut num_left_siblings = 0;
    let mut start_idx = node_idx;
    while start_idx != 0 {
        if start_idx & 1 != 0 {
            num_left_siblings += 1;
        }
        start_idx >>= 1;
    }
    num_left_siblings
}

/// Reconstruct the size of the tree.
/// This trick works by interpreting the binary representation of the index of a node as a *path*
/// to the node. If the lsb of the (remaining) path is a 1, turn right. Otherwise, turn left.
pub fn compute_tree_size(
    num_right_siblings: usize,
    index_of_last_included_leaf: usize,
) -> Result<usize, RangeProofError> {
    // Each right sibling converts a left turn into a right turn - replacing a
    // zero in the path with a one.
    let mut index_of_final_node = index_of_last_included_leaf;
    let mut mask = 1;
    let mut remaining_right_siblings = num_right_siblings;
    while remaining_right_siblings > 0 {
        if index_of_final_node & mask == 0 {
            index_of_final_node |= mask;
            remaining_right_siblings -= 1;
        }
        mask <<= 1;
        // Ensure that the next iteration won't overflow on 32 bit platforms
        if index_of_final_node == u32::MAX as usize {
            return Err(RangeProofError::TreeTooLarge);
        }
    }
    Ok(index_of_final_node + 1)
}
