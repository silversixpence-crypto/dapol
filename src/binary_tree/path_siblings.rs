//! Sibling nodes to the ones in a tree path.
//!
//! A path in a binary tree goes from a leaf node to the root node. For each
//! node (starting from the leaf node) one follows the path by moving to the
//! parent node; since the root node has no parent this is the end of the path.
//! A path is uniquely determined by a leaf node. It can thus be referred to as
//! the leaf node's path.
//!
//! [PathSiblings] contains all the nodes that are siblings to the ones in a
//! path. This structure is used in inclusion proof generation & verification.
//! One can construct a leaf node's path using the leaf node together with the
//! path siblings. See [crate][InclusionProof] for more details.
//!
//! There are 2 different algorithms for constructing the sibling nodes:
//! sequential and multi-threaded. If the tree store is full (i.e.
//! every node that was used to construct the root node is in the store) then
//! the 2 build algorithms are identical. The difference only comes in when the
//! store is not full (which is useful to save on space) and some nodes need to
//! be regenerated. Both algorithms are the same as those used for tree
//! construction so their implementations can be found in
//! [super][tree_builder][multi_threaded] and
//! [super][tree_builder][single_threaded].

use super::{BinaryTree, Coordinate, HiddenNodeContent, Mergeable, Node, MIN_STORE_DEPTH};
use crate::{
    binary_tree::multi_threaded::RecursionParamsBuilder, read_write_utils, utils::Consume,
};

use log::info;
use serde::{Deserialize, Serialize};

use std::{
    ffi::OsString,
    fmt::{self, Debug},
    path::PathBuf,
};

// -------------------------------------------------------------------------------------------------
// Main struct and build functions.

/// Contains all the information for a path in a [BinaryTree].
///
/// The `siblings` vector contains all the sibling nodes of the nodes in a leaf
/// node's path. The siblings are ordered from bottom layer (first) to root node
/// (last, not included). The leaf node + the siblings can be used to
/// reconstruct the actual nodes in the path as well as the root node.
#[derive(Debug, Serialize, Deserialize)]
pub struct PathSiblings<C: fmt::Display>(pub Vec<Node<C>>);

impl<C: fmt::Display> PathSiblings<C> {
    /// High performance build algorithm utilizing parallelization.
    /// Uses the same code in [super][tree_builder][multi_threaded].
    ///
    /// Note that the code only differs to
    /// [build_using_single_threaded_algorithm] if the tree store is not
    /// full and nodes have to be regenerated.
    ///
    /// `new_padding_node_content` is needed to generate new nodes.
    ///
    /// This function defines a closure for building nodes that are not found
    /// in the store, which is then passed to [build].
    pub fn build_using_multi_threaded_algorithm<F>(
        tree: &BinaryTree<C>,
        leaf_node: &Node<C>,
        new_padding_node_content: F,
    ) -> Result<PathSiblings<C>, PathSiblingsBuildError>
    where
        C: Debug + Clone + Mergeable + Send + Sync + 'static,
        F: Fn(&Coordinate) -> C + Send + Sync + 'static,
    {
        use super::tree_builder::multi_threaded::{build_node, RecursionParams};
        use dashmap::DashMap;
        use std::sync::Arc;

        let new_padding_node_content = Arc::new(new_padding_node_content);

        let node_builder = |coord: &Coordinate, tree: &BinaryTree<C>| {
            let params = RecursionParamsBuilder::default()
                // We don't want to store anything because the store already exists
                // inside the binary tree struct.
                .store_depth(MIN_STORE_DEPTH)
                .height(tree.height)
                .build_with_coord(coord);

            // TODO This cloning can be optimized away by changing the
            // build_node function to use a pre-populated map instead of the
            // mutable leaves vector.
            let mut leaf_nodes = Vec::<Node<C>>::new();
            for x in params.x_coord_range() {
                tree.get_node(&Coordinate { x, y: 0 }).consume(|node| {
                    leaf_nodes.push(node);
                });
            }

            // If the above vector is empty then we know this node needs to be a
            // padding node.
            if leaf_nodes.is_empty() {
                return Node {
                    coord: coord.clone(),
                    content: new_padding_node_content(coord),
                };
            }

            build_node(
                params,
                leaf_nodes,
                Arc::clone(&new_padding_node_content),
                Arc::new(DashMap::<Coordinate, Node<C>>::new()),
            )
        };

        PathSiblings::build(tree, leaf_node, node_builder)
    }

    /// Sequential build algorithm.
    /// Uses the same code in [super][tree_builder][single_threaded].
    ///
    /// Note that the code only differs to
    /// [build_using_multi_threaded_algorithm] if the tree store is not full
    /// and nodes have to be regenerated.
    ///
    /// `new_padding_node_content` is needed to generate new nodes.
    pub fn build_using_single_threaded_algorithm<F>(
        tree: &BinaryTree<C>,
        leaf_node: &Node<C>,
        new_padding_node_content: F,
    ) -> Result<PathSiblings<C>, PathSiblingsBuildError>
    where
        C: Debug + Clone + Mergeable,
        F: Fn(&Coordinate) -> C,
    {
        use super::tree_builder::single_threaded::build_node;

        let node_builder = |coord: &Coordinate, tree: &BinaryTree<C>| {
            // We don't want to store anything because the store already exists
            // inside the binary tree struct.
            let store_depth = MIN_STORE_DEPTH;

            let (x_coord_min, x_coord_max) = coord.subtree_x_coord_bounds();

            // TODO This copying of leaf nodes could be optimized away by
            // changing the build function to accept a map parameter as opposed
            // to the leaf node vector.
            let mut leaf_nodes = Vec::<Node<C>>::new();
            for x in x_coord_min..x_coord_max + 1 {
                tree.get_node(&Coordinate::bottom_layer_leaf_from(x))
                    .consume(|node| {
                        leaf_nodes.push(node);
                    });
            }

            // If the above vector is empty then we know this node needs to be a
            // padding node.
            if leaf_nodes.is_empty() {
                return Node {
                    coord: coord.clone(),
                    content: new_padding_node_content(coord),
                };
            }

            // TODO The leaf nodes are cloned and put into a store that is
            // dropped. We should have an option to not put anything in the
            // store, maybe by changing store_depth to be an enum.
            let (_, node) = build_node(
                leaf_nodes,
                &coord.to_height(),
                store_depth,
                &new_padding_node_content,
            );

            node
        };

        PathSiblings::build(tree, leaf_node, node_builder)
    }

    /// Private build function that is to be called only by
    /// [build_using_multi_threaded_algorithm] or
    /// [build_using_single_threaded_algorithm].
    ///
    /// The path is traced from the leaf node to the root node. At every layer
    /// in the tree the sibling node is grabbed from the store (or generated if
    /// it is not in the store) and added to the vector in [PathSiblings].
    ///
    /// Since the store is expected to contain all non-padding leaf nodes an
    /// error will be returned if the leaf node at the given x-coord is not
    /// found in the store.
    fn build<F>(
        tree: &BinaryTree<C>,
        leaf_node: &Node<C>,
        node_builder: F,
    ) -> Result<PathSiblings<C>, PathSiblingsBuildError>
    where
        C: Debug + Clone,
        F: Fn(&Coordinate, &BinaryTree<C>) -> Node<C>,
    {
        let mut siblings = Vec::with_capacity(tree.height().as_usize());
        let max_y_coord = tree.height().as_y_coord();
        let mut current_coord = leaf_node.coord().clone();

        for _y in 0..max_y_coord {
            let sibling_coord = current_coord.sibling_coord();

            let sibling = tree
                .get_node(&sibling_coord)
                .unwrap_or_else(|| node_builder(&sibling_coord, tree));

            siblings.push(sibling);
            current_coord = current_coord.parent_coord();
        }

        Ok(PathSiblings(siblings))
    }
}

// -------------------------------------------------------------------------------------------------
// Implementation.

impl<C: Debug + fmt::Display + Clone + Mergeable + PartialEq> PathSiblings<C> {
    /// Number of sibling nodes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Reconstructing each node in the path, from bottom layer
    /// to the root, using the given leaf and sibling nodes.
    ///
    /// This function does exactly the same as [construct_path] but does not
    /// store the intermediate nodes, only the final node.
    ///
    /// An error is returned if
    /// 1. The number of siblings is less than the min amount.
    /// 2. The [PathSiblings] data is invalid.
    pub fn construct_root_node(&self, leaf: &Node<C>) -> Result<Node<C>, PathSiblingsError> {
        use super::MIN_HEIGHT;

        if self.len() < MIN_HEIGHT.as_usize() {
            return Err(PathSiblingsError::TooFewSiblings);
        }

        let mut sibling_iterator = self.0.iter();
        let pair = MatchedPairRef::from(
            sibling_iterator
                .next()
                // We checked the length of the underlying vector above so this
                // should never panic.
                .expect("[Bug in path generation] There should be at least 1 sibling node"),
            leaf,
        )?;
        let mut parent = pair.merge();

        for node in sibling_iterator {
            let pair = MatchedPairRef::from(node, &parent)?;
            parent = pair.merge();
        }

        Ok(parent)
    }

    /// Return a vector containing only the nodes in the tree path.
    ///
    /// The path nodes have to be constructed using the leaf & sibling nodes in
    /// [PathSiblings] because they are not stored explicitly. The order of the
    /// returned path nodes is bottom first (leaf) and top last (root).
    ///
    /// This function does exactly the same as [construct_root_node] but stores
    /// all the intermediate nodes and returns them.
    ///
    /// An error is returned if
    /// 1. The number of siblings is less than the min amount.
    /// 2. The [PathSiblings] data is invalid.
    pub fn construct_path(&self, leaf: Node<C>) -> Result<Vec<Node<C>>, PathSiblingsError> {
        use super::MIN_HEIGHT;

        if self.len() < MIN_HEIGHT.as_usize() {
            return Err(PathSiblingsError::TooFewSiblings);
        }

        // +1 because the root node is included in the returned vector
        let mut nodes = Vec::<Node<C>>::with_capacity(self.len() + 1);

        nodes.push(leaf);

        for node in &self.0 {
            // this should never panic because we pushed the leaf node before the loop
            let parent = nodes
                .last()
                .expect("[Bug in path generation] Empty node vector");
            let pair = MatchedPairRef::from(node, parent)?;
            nodes.push(pair.merge());
        }

        Ok(nodes)
    }
}

// -------------------------------------------------------------------------------------------------
// Pretty printing

impl<C: fmt::Display + Serialize> PathSiblings<C> {
    /// Format the path & sibling nodes to a string.
    ///
    /// The path nodes are required as input, which can be generated using
    /// [construct_path].
    pub fn path_to_str(&self, path_nodes: &Vec<Node<C>>) -> String {
        use std::fmt::Write as _;

        let path_siblings = &self.0;
        let mut path_siblings_str = String::new();
        path_siblings.iter().for_each(|node| {
            path_siblings_str.push_str(&node.to_string());
            path_siblings_str.push_str("\n");
        });

        let mut path_nodes_str = String::new();
        path_nodes.iter().for_each(|node| {
            path_nodes_str.push_str(&node.to_string());
            path_nodes_str.push_str("\n");
        });

        let mut output_str = String::new();

        write!(&mut output_str, "\nNodes:\n{}", path_nodes_str)
            .expect("[Bug in path to string conversion] Cannot write to string object");

        write!(&mut output_str, "\nSiblings:\n{}", path_siblings_str)
            .expect("[Bug in path to string conversion] Cannot write to string object");

        output_str
    }
}

// -------------------------------------------------------------------------------------------------
// Pretty printing for C=HiddenNodeContent

/// Output shape for serializing to json.
#[derive(Debug, Serialize)]
struct PathWithSiblings {
    path_nodes: Vec<PrettyNode>,
    path_siblings: Vec<PrettyNode>,
}

/// This is basically a PrettyNode<HiddenNodeContent>.
///
/// This is used to write out path information to a neat json file.
//
// Note that we could have just serialized Node<C>, but the commitment and
// hash values serialize to different formats. The commitment serializes to
// [u8; 32], and the hash to a hex String. This is a pain to ingest with other
// software. One way to get both commitment & hash to be hex Strings is to
// simply do it manually, but that means knowing the specific type of C. So
// we cannot make this generic for all types of C.
#[derive(Debug, Serialize)]
struct PrettyNode {
    coord: Coordinate,
    hash: String,
    commitment: String,
}

impl From<Node<HiddenNodeContent>> for PrettyNode {
    /// Convert from a Node type to a PrettyNode.
    ///
    /// The hash & commitment string fields are populated with hexadecimal
    /// format of the underlying data.
    fn from(node: Node<HiddenNodeContent>) -> Self {
        use primitive_types::H256;
        use std::fmt::Write as _;

        let com_bytes = H256::from_slice(node.content.commitment.compress().as_bytes());
        let mut com_str = String::new();
        write!(&mut com_str, "{:x?}", com_bytes).expect("Cannot write to string object");

        let mut hash_str = String::new();
        write!(&mut hash_str, "{:x?}", node.content.hash).expect("Cannot write to string object");

        PrettyNode {
            coord: node.coord,
            hash: hash_str,
            commitment: com_str,
        }
    }
}

impl PathSiblings<HiddenNodeContent> {
    /// Write the path & sibling nodes to a json file.
    ///
    /// The path nodes are required as input for efficiency reasons (don't
    /// recompute in here if they have been computed elsewhere). The path nodes
    /// can be generated using [construct_nodes].
    ///
    /// Returns an error if the provided directory is invalid, or if the
    /// serialization process fails.
    pub fn write_path_to_json(
        self,
        path_nodes: Vec<Node<HiddenNodeContent>>,
        dir: PathBuf,
        mut file_name: OsString,
    ) -> Result<(), PathSiblingsWriteError> {
        if !dir.is_dir() {
            return Err(PathSiblingsWriteError::InvalidDirectory(
                dir.into_os_string(),
            ));
        }

        file_name.push(".json");
        let file_path = dir.join(file_name);

        let siblings = self.0.into_iter().map(PrettyNode::from).collect();
        let nodes = path_nodes.into_iter().map(PrettyNode::from).collect();

        let path_with_siblings = PathWithSiblings {
            path_nodes: nodes,
            path_siblings: siblings,
        };

        info!("Serializing inclusion proof path info to {:?}", file_path);

        read_write_utils::serialize_to_json_file(&path_with_siblings, file_path)?;

        Ok(())
    }
}

// -------------------------------------------------------------------------------------------------
// PathSiblings conversion.

impl<C: fmt::Display> PathSiblings<C> {
    /// Convert `PathSiblings<C>` to `PathSiblings<D>`.
    ///
    /// `convert` is called on each of the sibling nodes & leaf node.
    pub fn convert<B: From<C> + fmt::Display>(self) -> PathSiblings<B> {
        PathSiblings(self.0.into_iter().map(|node| node.convert()).collect())
    }
}

impl<C: fmt::Display> fmt::Display for PathSiblings<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            &self
                .0
                .iter()
                .map(|node| node.coord.to_string())
                .collect::<String>(),
        )
    }
}

// -------------------------------------------------------------------------------------------------
// Errors.

#[derive(thiserror::Error, Debug)]
pub enum PathSiblingsBuildError {
    #[error("The builder must be given a padding node generator function before building")]
    NoPaddingNodeContentGeneratorProvided,
    #[error("The builder must be given a tree before building")]
    NoTreeProvided,
    #[error("The builder must be given the x-coord of a leaf node before building")]
    NoLeafProvided,
    #[error("Leaf node not found in the tree ({coord:?})")]
    LeafNodeNotFound { coord: Coordinate },
}

#[derive(thiserror::Error, Debug)]
pub enum PathSiblingsError {
    #[error("Provided node ({sibling_given:?}) is not a sibling of the calculated node ({node_that_needs_sibling:?})")]
    InvalidSibling {
        node_that_needs_sibling: Coordinate,
        sibling_given: Coordinate,
    },
    #[error("Too few siblings")]
    TooFewSiblings,
}

#[derive(thiserror::Error, Debug)]
pub enum PathSiblingsWriteError {
    #[error("Provided string '{0:?}' does not point to a valid directory")]
    InvalidDirectory(OsString),
    #[error("Error serializing")]
    SerdeError(#[from] crate::read_write_utils::ReadWriteError),
}

// -------------------------------------------------------------------------------------------------
// Supporting structs and methods.

/// A reference to a left sibling node.
///
/// It is like [super][sparse_binary_tree][LeftSibling] but does not own the
/// underlying node. The purpose of this type is for efficiency gains over
/// [super][sparse_binary_tree][LeftSibling] when ownership of the Node type is
/// not needed.
struct LeftSiblingRef<'a, C: fmt::Display>(&'a Node<C>);

/// A reference to a right sibling node.
///
/// It is like [super][sparse_binary_tree][RightSibling] but does not own the
/// underlying node. The purpose of this type is for efficiency gains over
/// [super][sparse_binary_tree][RightSibling] when ownership of the Node type is
/// not needed.
struct RightSiblingRef<'a, C: fmt::Display>(&'a Node<C>);

/// A reference to a pair of left and right sibling nodes.
///
/// It is like [super][sparse_binary_tree][MatchedPair] but does not own the
/// underlying node. The purpose of this type is for efficiency gains over
/// [super][sparse_binary_tree][MatchedPair] when ownership of the Node type is
/// not needed.
struct MatchedPairRef<'a, C: fmt::Display> {
    left: LeftSiblingRef<'a, C>,
    right: RightSiblingRef<'a, C>,
}

impl<'a, C: Mergeable + fmt::Display> MatchedPairRef<'a, C> {
    /// Create a parent node by merging the 2 nodes in the pair.
    fn merge(&self) -> Node<C> {
        Node {
            coord: Coordinate {
                x: self.left.0.coord.x / 2,
                y: self.left.0.coord.y + 1,
            },
            content: C::merge(&self.left.0.content, &self.right.0.content),
        }
    }

    /// Construct a [MatchedPairRef] using the 2 given nodes.
    /// Only build the pair if the 2 nodes are siblings, otherwise return an
    /// error.
    fn from(left: &'a Node<C>, right: &'a Node<C>) -> Result<Self, PathSiblingsError>
    where
        C: Clone,
    {
        if right.is_right_sibling_of(left) {
            Ok(MatchedPairRef {
                left: LeftSiblingRef(left),
                right: RightSiblingRef(right),
            })
        } else if right.is_left_sibling_of(left) {
            Ok(MatchedPairRef {
                left: LeftSiblingRef(right),
                right: RightSiblingRef(left),
            })
        } else {
            Err(PathSiblingsError::InvalidSibling {
                node_that_needs_sibling: right.coord.clone(),
                sibling_given: left.coord.clone(),
            })
        }
    }
}

// -------------------------------------------------------------------------------------------------
// Unit tests.

// TODO need to test that when the node is expected to be in the store the build
// function is not called (need to have mocking for this)

// TODO Fuzz on the tree height, and the store depth.

// TODO tests for multi tree build then single path build, and vice versa.

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;
    use crate::binary_tree::utils::test_utils::{
        full_bottom_layer, generate_padding_closure, single_leaf, sparse_leaves, TestContent,
    };

    #[test]
    fn path_works_for_full_base_layer_single_threaded() {
        let height = Height::expect_from(8u8);

        let leaf_nodes = full_bottom_layer(&height);

        let tree_single_threaded = BinaryTreeBuilder::new()
            .with_height(height)
            .with_store_depth(MIN_STORE_DEPTH)
            .with_leaf_nodes(leaf_nodes.clone())
            .build_using_single_threaded_algorithm(generate_padding_closure())
            .unwrap();

        let leaf_node = tree_single_threaded.get_leaf_node(10).unwrap();

        let siblings = PathSiblings::build_using_single_threaded_algorithm(
            &tree_single_threaded,
            &leaf_node,
            generate_padding_closure(),
        )
        .expect("PathSiblings generation should have been successful");

        assert_eq!(
            siblings.len() as u8,
            tree_single_threaded.height().as_y_coord()
        );
        assert_eq!(
            &siblings.construct_root_node(&leaf_node).unwrap(),
            tree_single_threaded.root()
        );
    }

    #[test]
    fn path_works_for_full_base_layer_multi_threaded() {
        let height = Height::expect_from(8u8);

        let leaf_nodes = full_bottom_layer(&height);

        let tree_multi_threaded = BinaryTreeBuilder::new()
            .with_height(height)
            .with_store_depth(MIN_STORE_DEPTH)
            .with_leaf_nodes(leaf_nodes.clone())
            .build_using_multi_threaded_algorithm(generate_padding_closure())
            .unwrap();

        let leaf_node = tree_multi_threaded.get_leaf_node(10).unwrap();

        let siblings = PathSiblings::build_using_multi_threaded_algorithm(
            &tree_multi_threaded,
            &leaf_node,
            generate_padding_closure(),
        )
        .expect("PathSiblings generation should have been successful");

        assert_eq!(
            siblings.len() as u8,
            tree_multi_threaded.height().as_y_coord()
        );
        assert_eq!(
            &siblings.construct_root_node(&leaf_node).unwrap(),
            tree_multi_threaded.root()
        );
    }

    #[test]
    fn path_works_for_sparse_leaves_single_threaded() {
        let height = Height::expect_from(8u8);

        let leaf_nodes = sparse_leaves(&height);

        let tree_single_threaded = BinaryTreeBuilder::new()
            .with_height(height)
            .with_leaf_nodes(leaf_nodes.clone())
            .with_store_depth(MIN_STORE_DEPTH)
            .build_using_single_threaded_algorithm(generate_padding_closure())
            .unwrap();

        let leaf_node = tree_single_threaded.get_leaf_node(6).unwrap();

        let siblings = PathSiblings::build_using_single_threaded_algorithm(
            &tree_single_threaded,
            &leaf_node,
            generate_padding_closure(),
        )
        .expect("PathSiblings generation should have been successful");

        assert_eq!(
            siblings.len() as u8,
            tree_single_threaded.height().as_y_coord()
        );
        assert_eq!(
            &siblings.construct_root_node(&leaf_node).unwrap(),
            tree_single_threaded.root()
        );
    }

    #[test]
    fn path_works_for_sparse_leaves_multi_threaded() {
        let height = Height::expect_from(8u8);

        let leaf_nodes = sparse_leaves(&height);

        let tree_multi_threaded = BinaryTreeBuilder::new()
            .with_height(height)
            .with_leaf_nodes(leaf_nodes.clone())
            .with_store_depth(MIN_STORE_DEPTH)
            .build_using_multi_threaded_algorithm(generate_padding_closure())
            .unwrap();

        let leaf_node = tree_multi_threaded.get_leaf_node(6).unwrap();

        let siblings = PathSiblings::build_using_multi_threaded_algorithm(
            &tree_multi_threaded,
            &leaf_node,
            generate_padding_closure(),
        )
        .expect("PathSiblings generation should have been successful");

        assert_eq!(
            siblings.len() as u8,
            tree_multi_threaded.height().as_y_coord()
        );
        assert_eq!(
            &siblings.construct_root_node(&leaf_node).unwrap(),
            tree_multi_threaded.root()
        );
    }

    #[test]
    fn path_works_for_single_leaf_single_threaded() {
        let height = Height::expect_from(8u8);

        for i in 0..height.max_bottom_layer_nodes() {
            let leaf_node = vec![single_leaf(i)];

            let tree_single_threaded = BinaryTreeBuilder::new()
                .with_height(height)
                .with_leaf_nodes(leaf_node.clone())
                .with_store_depth(MIN_STORE_DEPTH)
                .build_using_single_threaded_algorithm(generate_padding_closure())
                .unwrap();

            let leaf_node = tree_single_threaded.get_leaf_node(i).unwrap();

            let siblings = PathSiblings::build_using_single_threaded_algorithm(
                &tree_single_threaded,
                &leaf_node,
                generate_padding_closure(),
            )
            .expect("PathSiblings generation should have been successful");

            assert_eq!(
                siblings.len() as u8,
                tree_single_threaded.height().as_y_coord()
            );
            assert_eq!(
                &siblings.construct_root_node(&leaf_node).unwrap(),
                tree_single_threaded.root()
            );
        }
    }

    #[test]
    fn path_works_for_multi_leaf_multi_threaded() {
        let height = Height::expect_from(8u8);

        for x_coord in 0..height.max_bottom_layer_nodes() {
            let leaf_node = vec![single_leaf(x_coord)];

            let tree_multi_threaded = BinaryTreeBuilder::new()
                .with_height(height)
                .with_leaf_nodes(leaf_node.clone())
                .with_store_depth(MIN_STORE_DEPTH)
                .build_using_multi_threaded_algorithm(generate_padding_closure())
                .unwrap();

            let leaf_node = tree_multi_threaded.get_leaf_node(x_coord).unwrap();

            let siblings = PathSiblings::build_using_multi_threaded_algorithm(
                &tree_multi_threaded,
                &leaf_node,
                generate_padding_closure(),
            )
            .expect("PathSiblings build should have been successful");

            assert_eq!(
                siblings.len() as u8,
                tree_multi_threaded.height().as_y_coord()
            );
            assert_eq!(
                &siblings.construct_root_node(&leaf_node).unwrap(),
                tree_multi_threaded.root()
            );
        }
    }
}
