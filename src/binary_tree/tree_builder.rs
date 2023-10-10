//! Builder pattern for the binary tree.
//!
//! There are 2 options for builder type:
//! - [single_threaded]
//! - [multi_threaded]
//! Both require a vector of leaf nodes (which will live on the bottom layer
//! of the tree) and the tree height.

use std::fmt::Debug;

use super::{BinaryTree, Coordinate, Mergeable, MIN_HEIGHT};

pub mod multi_threaded;
pub mod single_threaded;

/// This equates to half of the layers being stored.
/// `height / DEFAULT_STORE_DEPTH_RATIO`
static DEFAULT_STORE_DEPTH_RATIO: u8 = 2;

/// The root node is not actually put in the hashmap because it is
/// returned along with the hashmap, but it is considered to be stored so
/// `store_depth` must at least be 1.
pub static MIN_STORE_DEPTH: u8 = 1;

// -------------------------------------------------------------------------------------------------
// Main structs.

/// Parameters for building a [super][BinaryTree].
///
/// `leaf_nodes` is the set of non-padding bottom-layer leaves of the tree.
/// `store_depth` determines how many nodes placed in the store.
///
/// By default only the non-padding leaf nodes and the root node are placed in
/// the store. This can be increased using the `store_depth` parameter. If
/// `store_depth == 1` then only the root node is stored and if
/// `store_depth == n` then the root node plus the next `n-1` layers from the
/// root node down are stored. So if `store_depth == height` then all the nodes
/// are stored.
#[derive(Debug)]
pub struct TreeBuilder<C> {
    height: Option<u8>,
    leaf_nodes: Option<Vec<InputLeafNode<C>>>,
    store_depth: Option<u8>,
}

/// A simpler version of the [Node] struct that is used as input to
/// the tree builder. Since the node parameters are all assumed to be on the
/// bottom layer of the tree only the x-coord is required, the y-coord is fixed
/// and determined by the tree height.
#[derive(Debug, Clone)]
pub struct InputLeafNode<C> {
    pub content: C,
    pub x_coord: u64,
}

// -------------------------------------------------------------------------------------------------
// Implementation.

/// Example:
/// ```
/// let tree = TreeBuilder::new()
///     .with_height(height)?
///     .with_leaf_nodes(leaf_nodes)?
///     .build_using_single_threaded_algorithm(new_padding_node_content)?;
/// ```
impl<C> TreeBuilder<C>
where
    C: Clone + Mergeable + 'static, /* The static is needed when the single threaded builder
                                     * builds the boxed hashmap. */
{
    pub fn new() -> Self {
        TreeBuilder {
            height: None,
            leaf_nodes: None,
            store_depth: None,
        }
    }

    /// Set the height of the tree.
    /// Will return an error if `height` is <= the min allowed height.
    pub fn with_height(mut self, height: u8) -> Self {
        self.height = Some(height);
        self
    }

    /// The leaf nodes are those that correspond to the data that we are trying
    /// to represent in the tree. All leaf nodes are assumed to be on the bottom
    /// layer of the tree. Note the nodes do not have to be pre-sorted, sorting
    /// will occur downstream.
    /// Will return an error if `leaf_nodes` is empty.
    pub fn with_leaf_nodes(mut self, leaf_nodes: Vec<InputLeafNode<C>>) -> Self {
        self.leaf_nodes = Some(leaf_nodes);
        self
    }

    /// `store_depth` determines how many layers are placed in the store. If
    /// `store_depth == 1` then only the root node is stored and if
    /// `store_depth == 2` then the root node and the next layer down are
    /// stored.
    ///
    /// The fewer nodes that are place in the store the smaller the serialized
    /// tree file will be, but the more time it will take to generate inclusion
    /// proofs since more nodes may have to be built from scratch.
    pub fn with_store_depth(mut self, store_depth: u8) -> Self {
        self.store_depth = Some(store_depth);
        self
    }

    /// High performance build algorithm utilizing parallelization.
    pub fn build_using_multi_threaded_algorithm<F>(
        self,
        new_padding_node_content: F,
    ) -> Result<BinaryTree<C>, TreeBuildError>
    where
        C: Debug + Send + Sync + 'static,
        F: Fn(&Coordinate) -> C + Send + Sync + 'static,
    {
        let height = self.height()?;
        let store_depth = self.store_depth(height);
        let input_leaf_nodes = self.leaf_nodes(height)?;

        multi_threaded::build_tree(
            height,
            store_depth,
            input_leaf_nodes,
            new_padding_node_content,
        )
    }

    /// Regular build algorithm.
    pub fn build_using_single_threaded_algorithm<F>(self,
                                                    new_padding_node_content: F,
    ) -> Result<BinaryTree<C>, TreeBuildError>
    where
        C: Debug,
        F: Fn(&Coordinate) -> C,
    {
        let height = self.height()?;
        let store_depth = self.store_depth(height);
        let input_leaf_nodes = self.leaf_nodes(height)?;

        single_threaded::build_tree(height, store_depth, input_leaf_nodes, new_padding_node_content)
    }

    /// Use the height of the tree to determine store depth by dividing it by
    /// the default ratio.
    fn store_depth(&self, height: u8) -> u8 {
        self.store_depth
            .unwrap_or(height / DEFAULT_STORE_DEPTH_RATIO)
    }

    /// Called by children builders to check the bounds of the `height` field.
    fn height(&self) -> Result<u8, TreeBuildError> {
        let height = self.height.ok_or(TreeBuildError::NoHeightProvided)?;
        if height < MIN_HEIGHT {
            return Err(TreeBuildError::HeightTooSmall);
        }
        Ok(height)
    }

    /// Called by children builders to check the bounds of the `leaf_nodes`
    /// field.
    fn leaf_nodes(self, height: u8) -> Result<Vec<InputLeafNode<C>>, TreeBuildError> {
        use super::{max_bottom_layer_nodes, ErrUnlessTrue};

        let leaf_nodes = self.leaf_nodes.ok_or(TreeBuildError::NoLeafNodesProvided)?;

        if leaf_nodes.len() == 0 {
            return Err(TreeBuildError::EmptyLeaves);
        }

        let max_leaf_nodes = max_bottom_layer_nodes(height);

        if leaf_nodes.len() > max_leaf_nodes as usize {
            return Err(TreeBuildError::TooManyLeaves);
        }

        // Make sure all x-coord < max.
        leaf_nodes
            .last()
            .map(|node| node.x_coord < max_leaf_nodes)
            .err_unless_true(TreeBuildError::InvalidXCoord)?;

        Ok(leaf_nodes)
    }
}

/// Check that no 2 leaf nodes share the same x-coord.
/// `leaf_nodes` is expected to be sorted by x-coord.
fn verify_no_duplicate_leaves<C>(leaf_nodes: &Vec<InputLeafNode<C>>) -> Result<(), TreeBuildError> {
    use super::ErrOnSome;

    let i = leaf_nodes.iter();
    let i_plus_1 = {
        let mut i = leaf_nodes.iter();
        i.next();
        i
    };

    i.zip(i_plus_1)
        .find(|(prev, curr)| prev.x_coord == curr.x_coord)
        .err_on_some(TreeBuildError::DuplicateLeaves)?;

    Ok(())
}

// -------------------------------------------------------------------------------------------------
// Errors.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum TreeBuildError {
    #[error("The builder must be given leaf nodes before building")]
    NoLeafNodesProvided,
    #[error("The builder must be given a height before building")]
    NoHeightProvided,
    #[error("The builder must be given a padding node generator function before building")]
    NoPaddingNodeContentGeneratorProvided,
    #[error("Too many leaves for the given height")]
    TooManyLeaves,
    #[error("Leaf nodes cannot be empty")]
    EmptyLeaves,
    #[error("X coords for leaves must be less than 2^height")]
    InvalidXCoord,
    #[error("Height cannot be smaller than {MIN_HEIGHT:?}")]
    HeightTooSmall,
    #[error("Not allowed to have more than 1 leaf with the same x-coord")]
    DuplicateLeaves,

    #[error("Could not get ownership of the store in the multi-threaded builder")]
    StoreOwnershipFailure,
}

// -------------------------------------------------------------------------------------------------
// Unit tests.

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;
    use crate::binary_tree::utils::test_utils::{
        full_bottom_layer, get_padding_function, single_leaf, sparse_leaves, TestContent,
    };

    use crate::testing_utils::{assert_err, assert_err_simple};

    use primitive_types::H256;
    use rand::{thread_rng, Rng};

    // =========================================================================
    // Happy cases for both single- and multi-threaded builders.
    // All tests here compare the trees from the 2 build algorithms, which gives
    // a fair amount of confidence in their correctness.

    // TODO test all edge cases where the first and last 2 nodes are either all
    // present or all not or partially present

    // TODO test more leaf node configurations?

    #[test]
    fn multi_and_single_give_same_root_sparse_leaves() {
        let height = 8u8;

        let leaf_nodes = sparse_leaves(height);

        let single_threaded = TreeBuilder::new()
            .with_height(height)
            .with_leaf_nodes(leaf_nodes.clone())
            .build_using_single_threaded_algorithm(get_padding_function())
            .unwrap();

        let multi_threaded = TreeBuilder::new()
            .with_height(height)
            .with_leaf_nodes(leaf_nodes)
            .build_using_multi_threaded_algorithm(get_padding_function())
            .unwrap();

        assert_eq!(single_threaded.root, multi_threaded.root);
        assert_eq!(single_threaded.height, multi_threaded.height);
        assert_eq!(single_threaded.height, height);
    }

    #[test]
    fn multi_and_single_give_same_root_full_tree() {
        let height = 8u8;

        let leaf_nodes = full_bottom_layer(height);

        let single_threaded = TreeBuilder::new()
            .with_height(height)
            .with_leaf_nodes(leaf_nodes.clone())
            .build_using_single_threaded_algorithm(get_padding_function())
            .unwrap();

        let multi_threaded = TreeBuilder::new()
            .with_height(height)
            .with_leaf_nodes(leaf_nodes)
            .build_using_multi_threaded_algorithm(get_padding_function())
            .unwrap();

        assert_eq!(single_threaded.root, multi_threaded.root);
        assert_eq!(single_threaded.height, multi_threaded.height);
        assert_eq!(single_threaded.height, height);
    }

    #[test]
    fn multi_and_single_give_same_root_single_leaf() {
        let height = 8u8;

        for i in 0..max_bottom_layer_nodes(height) {
            let leaf_node = vec![single_leaf(i as u64, height)];

            let single_threaded = TreeBuilder::new()
                .with_height(height)
                .with_leaf_nodes(leaf_node.clone())
                .build_using_single_threaded_algorithm(get_padding_function())
                .unwrap();

            let multi_threaded = TreeBuilder::new()
                .with_height(height)
                .with_leaf_nodes(leaf_node)
                .build_using_multi_threaded_algorithm(get_padding_function())
                .unwrap();

            assert_eq!(single_threaded.root, multi_threaded.root);
            assert_eq!(single_threaded.height, multi_threaded.height);
            assert_eq!(single_threaded.height, height);
        }
    }

    // =========================================================================

    #[test]
    fn err_when_parent_builder_height_not_set() {
        let height = 4;
        let leaf_nodes = full_bottom_layer(height);
        let res = TreeBuilder::new().with_leaf_nodes(leaf_nodes).height();

        // cannot use assert_err because it requires Func to have the Debug trait
        assert_err_simple!(res, Err(TreeBuildError::NoHeightProvided));
    }

    #[test]
    fn err_when_parent_builder_leaf_nodes_not_set() {
        let height = 4;
        let res = TreeBuilder::<TestContent>::new()
            .with_height(height)
            .leaf_nodes(height);

        // cannot use assert_err because it requires Func to have the Debug trait
        assert_err_simple!(res, Err(TreeBuildError::NoLeafNodesProvided));
    }

    #[test]
    fn err_for_empty_leaves() {
        let height = 5;
        let res = TreeBuilder::<TestContent>::new()
            .with_height(height)
            .with_leaf_nodes(Vec::new())
            .leaf_nodes(height);
        assert_err!(res, Err(TreeBuildError::EmptyLeaves));
    }

    #[test]
    fn err_when_height_too_small() {
        assert!(MIN_HEIGHT > 0, "Invalid min height {}", MIN_HEIGHT);
        let height = MIN_HEIGHT - 1;
        let res = TreeBuilder::<TestContent>::new()
            .with_height(height)
            .height();
        assert_err!(res, Err(TreeBuildError::HeightTooSmall));
    }

    #[test]
    fn err_for_too_many_leaves() {
        let height = 8u8;
        let mut leaf_nodes = full_bottom_layer(height);

        leaf_nodes.push(InputLeafNode::<TestContent> {
            x_coord: max_bottom_layer_nodes(height) + 1,
            content: TestContent {
                hash: H256::random(),
                value: thread_rng().gen(),
            },
        });

        let res = TreeBuilder::new()
            .with_height(height)
            .with_leaf_nodes(leaf_nodes)
            .leaf_nodes(height);

        assert_err!(res, Err(TreeBuildError::TooManyLeaves));
    }

    #[test]
    fn err_for_duplicate_leaves() {
        let height = 4;
        let mut leaf_nodes = sparse_leaves(height);
        leaf_nodes.push(single_leaf(leaf_nodes.last().unwrap().x_coord, height));

        println!("leaf nodes {:?}", leaf_nodes);
        let res = verify_no_duplicate_leaves(&leaf_nodes);

        // cannot use assert_err because it requires Func to have the Debug trait
        assert_err_simple!(res, Err(TreeBuildError::DuplicateLeaves));
    }

    #[test]
    fn no_err_if_duplicates_but_not_sorted() {
        let height = 4;
        let mut leaf_nodes = sparse_leaves(height);
        leaf_nodes.push(single_leaf(leaf_nodes.get(0).unwrap().x_coord, height));

        println!("leaf nodes {:?}", leaf_nodes);
        let _ = verify_no_duplicate_leaves(&leaf_nodes).unwrap();
    }

    #[test]
    fn no_err_if_no_duplicates() {
        let height = 4;
        let mut leaf_nodes = sparse_leaves(height);
        let _ = verify_no_duplicate_leaves(&leaf_nodes).unwrap();
    }
}