//! Implementation of the generic node content type.
//!
//! The [crate][binary_tree][BinaryTree] implementation uses a generic value for
//! the content so that all the code can be easily reused for different types of
//! nodes.
//!
//! In order to implement a node content type one must create a struct
//! containing the data for the node, and then implement the [Mergeable] trait
//! which takes 2 children nodes and combines them to make a parent node.

mod full_node;
pub use full_node::FullNodeContent;

mod hidden_node;
pub use hidden_node::HiddenNodeContent;

/// The generic content type of a [Node] must implement this trait to allow 2
/// sibling nodes to be combined to make a new parent node.
pub trait Mergeable {
    fn merge(left_sibling: &Self, right_sibling: &Self) -> Self;
}
