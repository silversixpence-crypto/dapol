//! TODO add module-level documentation
//! TODO add more detailed documentation for all public functions/structs

mod sparse_binary_tree;
pub use sparse_binary_tree::{InputLeafNode, SparseBinaryTree, TreeBuildError, Builder, MultiThreadedBuilder, SingleThreadedBuilder};

mod multi_threaded_builder;
mod single_threaded_builder;

mod binary_tree_path;
pub use binary_tree_path::{Path, PathError};

// -------------------------------------------------------------------------------------------------
// Main structs.

/// Fundamental structure of the tree, each element of the tree is a Node.
/// The data contained in the node is completely generic, requiring only to have
/// an associated merge function.
#[derive(Clone, Debug, PartialEq)]
pub struct Node<C: Clone> {
    pub coord: Coordinate,
    pub content: C,
}

/// Index of a [Node] in the tree.
/// `y` is the vertical index (height) of the Node (0 being the bottom of the
/// tree) and `x` is the horizontal index of the Node (0 being the leftmost
/// index).
#[derive(PartialEq, Eq, Hash, Debug, Clone)]
pub struct Coordinate {
    pub y: u8, // from 0 to height
    // TODO this enforces a max tree height of 2^64 so we should make sure that is accounted for in
    // other bits of the code, and make it easy to upgrade this max to something larger in the
    // future
    pub x: u64, // from 0 to 2^y
}

/// The generic content type of a [Node] must implement this trait to allow 2
/// sibling nodes to be combined to make a new parent node.
pub trait Mergeable {
    fn merge(left_sibling: &Self, right_sibling: &Self) -> Self;
}

// -------------------------------------------------------------------------------------------------
// Implementations.

impl Coordinate {
    /// Copy internal data and return as bytes.
    /// https://stackoverflow.com/questions/71788974/concatenating-two-u16s-to-a-single-array-u84
    pub fn as_bytes(&self) -> [u8; 32] {
        let mut c = [0u8; 32];
        let (left, mid) = c.split_at_mut(1);
        left.copy_from_slice(&self.y.to_le_bytes());
        let (mid, _right) = mid.split_at_mut(8);
        mid.copy_from_slice(&self.x.to_le_bytes());
        c
    }
}

impl<C: Clone> Node<C> {
    /// Returns left if this node is a left sibling and vice versa for right.
    /// Since we are working with a binary tree we can tell if the node is a left sibling of the above layer by checking the x_coord modulus 2.
    /// Since x_coord starts from 0 we check if the modulus is equal to 0.
    fn node_orientation(&self) -> NodeOrientation {
        if self.coord.x % 2 == 0 {
            NodeOrientation::Left
        } else {
            NodeOrientation::Right
        }
    }

    /// Return true if self is a) a left sibling and b) lives just to the left
    /// of the other node.
    fn is_left_sibling_of(&self, other: &Node<C>) -> bool {
        match self.node_orientation() {
            NodeOrientation::Left => {
                self.coord.y == other.coord.y && self.coord.x + 1 == other.coord.x
            }
            NodeOrientation::Right => false,
        }
    }

    /// Return true if self is a) a right sibling and b) lives just to the right
    /// of the other node.
    fn is_right_sibling_of(&self, other: &Node<C>) -> bool {
        match self.node_orientation() {
            NodeOrientation::Left => false,
            NodeOrientation::Right => {
                self.coord.x > 0
                    && self.coord.y == other.coord.y
                    && self.coord.x - 1 == other.coord.x
            }
        }
    }

    /// Return the coordinates of this node's sibling, whether that be a right
    /// or a left sibling.
    fn get_sibling_coord(&self) -> Coordinate {
        match self.node_orientation() {
            NodeOrientation::Left => Coordinate {
                y: self.coord.y,
                x: self.coord.x + 1,
            },
            NodeOrientation::Right => Coordinate {
                y: self.coord.y,
                x: self.coord.x - 1,
            },
        }
    }

    /// Return the coordinates of this node's parent.
    /// The x-coord divide-by-2 works for both left _and_ right siblings because
    /// of truncation. Note that this function can be misused if tree height
    /// is not used to bound the y-coord from above.
    fn get_parent_coord(&self) -> Coordinate {
        Coordinate {
            y: self.coord.y + 1,
            x: self.coord.x / 2,
        }
    }

    /// Convert a `Node<C>` to a `Node<B>`.
    fn convert<B: Clone + From<C>>(self) -> Node<B> {
        Node {
            content: self.content.into(),
            coord: self.coord,
        }
    }
}

impl<C: Clone> InputLeafNode<C> {
    /// Convert the simpler node type to the actual Node type.
    fn to_node(self) -> Node<C> {
        Node {
            content: self.content,
            coord: Coordinate {
                x: self.x_coord,
                y: 0,
            },
        }
    }
}

// -------------------------------------------------------------------------------------------------
// Supporting structs.

/// Used to organise nodes into left/right siblings.
enum NodeOrientation {
    Left,
    Right,
}

/// Used to orient nodes inside a sibling pair so that the compiler can
/// guarantee a left node is actually a left node.
enum Sibling<C: Clone> {
    Left(LeftSibling<C>),
    Right(RightSibling<C>),
}

/// Simply holds a Node under the designated 'LeftSibling' name.
struct LeftSibling<C: Clone>(Node<C>);

/// Simply holds a Node under the designated 'RightSibling' name.
struct RightSibling<C: Clone>(Node<C>);

/// A pair of sibling nodes.
struct MatchedPair<C: Mergeable + Clone> {
    left: LeftSibling<C>,
    right: RightSibling<C>,
}

// -------------------------------------------------------------------------------------------------
// Supporting struct implementations.

impl<C: Clone> LeftSibling<C> {
    /// New padding nodes are given by a closure. Why a closure? Because
    /// creating a padding node may require context outside of this scope, where
    /// type C is defined, for example.
    fn new_sibling_padding_node<F>(&self, new_padding_node_content: &F) -> RightSibling<C>
    where
        F: Fn(&Coordinate) -> C,
    {
        let coord = self.0.get_sibling_coord();
        let content = new_padding_node_content(&coord);
        let node = Node { coord, content };
        RightSibling(node)
    }
    fn from_node(node: Node<C>) -> Self {
        // TODO panic if node is not a left sibling
        Self(node)
    }
}

impl<C: Clone> RightSibling<C> {
    /// New padding nodes are given by a closure. Why a closure? Because
    /// creating a padding node may require context outside of this scope, where
    /// type C is defined, for example.
    fn new_sibling_padding_node<F>(&self, new_padding_node_content: &F) -> LeftSibling<C>
    where
        F: Fn(&Coordinate) -> C,
    {
        let coord = self.0.get_sibling_coord();
        let content = new_padding_node_content(&coord);
        let node = Node { coord, content };
        LeftSibling(node)
    }
    fn from_node(node: Node<C>) -> Self {
        // TODO panic if node is not a left sibling
        Self(node)
    }
}

impl<C: Clone> Sibling<C> {
    /// Move a generic node into the left/right sibling type.
    fn from_node(node: Node<C>) -> Self {
        match node.node_orientation() {
            NodeOrientation::Left => Sibling::Left(LeftSibling(node)),
            NodeOrientation::Right => Sibling::Right(RightSibling(node)),
        }
    }
}

impl<C: Mergeable + Clone> MatchedPair<C> {
    /// Create a parent node by merging the 2 nodes in the pair.
    fn merge(&self) -> Node<C> {
        Node {
            coord: Coordinate {
                y: self.left.0.coord.y + 1,
                x: self.left.0.coord.x / 2,
            },
            content: C::merge(&self.left.0.content, &self.right.0.content),
        }
    }
}

// -------------------------------------------------------------------------------------------------
// Helper functions.

/// The maximum number of leaf nodes on the bottom layer of the binary tree.
/// TODO latex `max = 2^(height-1)`
pub fn num_bottom_layer_nodes(height: u8) -> u64 {
    2u64.pow(height as u32 - 1)
}

// -------------------------------------------------------------------------------------------------
// Test utils for sub-modules.

#[cfg(test)]
mod test_utils {
    use super::*;
    use primitive_types::H256;

    #[derive(Default, Clone, Debug, PartialEq)]
    pub struct TestContent {
        pub value: u32,
        pub hash: H256,
    }

    pub trait H256Finalizable {
        fn finalize_as_h256(&self) -> H256;
    }

    impl H256Finalizable for blake3::Hasher {
        fn finalize_as_h256(&self) -> H256 {
            H256(self.finalize().as_bytes().clone())
        }
    }

    impl Mergeable for TestContent {
        fn merge(left_sibling: &Self, right_sibling: &Self) -> Self {
            // C(parent) = C(L) + C(R)
            let parent_value = left_sibling.value + right_sibling.value;

            // H(parent) = Hash(C(L) | C(R) | H(L) | H(R))
            let parent_hash = {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&left_sibling.value.to_le_bytes());
                hasher.update(&right_sibling.value.to_le_bytes());
                hasher.update(left_sibling.hash.as_bytes());
                hasher.update(right_sibling.hash.as_bytes());
                hasher.finalize_as_h256() // TODO double check the output of this thing
            };

            TestContent {
                value: parent_value,
                hash: parent_hash,
            }
        }
    }

    pub fn get_padding_function() -> impl Fn(&Coordinate) -> TestContent {
        |_coord: &Coordinate| -> TestContent {
            TestContent {
                value: 0,
                hash: H256::default(),
            }
        }
    }

    // tree has a full bottom layer, and, subsequently, all other layers
    pub fn full_tree() -> (SparseBinaryTree<TestContent>, u8) {
        let height = 4u8;
        let mut leaves = Vec::<InputLeafNode<TestContent>>::new();

        for i in 0..2usize.pow(height as u32 - 1) {
            leaves.push(InputLeafNode::<TestContent> {
                x_coord: i as u64,
                content: TestContent {
                    hash: H256::default(),
                    value: i as u32,
                },
            });
        }

        let tree = SparseBinaryTree::new(leaves, height, &get_padding_function())
            .expect("Tree construction should not have produced an error");

        (tree, height)
    }

    // only 1 bottom-layer leaf node is present in the whole tree
    pub fn tree_with_single_leaf(
        x_coord_of_leaf: u64,
        height: u8,
    ) -> SparseBinaryTree<TestContent> {
        let leaf = InputLeafNode::<TestContent> {
            x_coord: x_coord_of_leaf,
            content: TestContent {
                hash: H256::default(),
                value: 1,
            },
        };

        let tree = SparseBinaryTree::new(vec![leaf], height, &get_padding_function())
            .expect("Tree construction should not have produced an error");

        tree
    }

    // a selection of leaves dispersed sparsely along the bottom layer
    pub fn tree_with_sparse_leaves() -> (SparseBinaryTree<TestContent>, u8) {
        let height = 5u8;

        // note the nodes are not in order here (wrt x-coord) so this test also somewhat covers the sorting code in the constructor
        let leaf_0 = InputLeafNode::<TestContent> {
            x_coord: 6,
            content: TestContent {
                hash: H256::default(),
                value: 1,
            },
        };
        let leaf_1 = InputLeafNode::<TestContent> {
            x_coord: 1,
            content: TestContent {
                hash: H256::default(),
                value: 2,
            },
        };
        let leaf_2 = InputLeafNode::<TestContent> {
            x_coord: 0,
            content: TestContent {
                hash: H256::default(),
                value: 3,
            },
        };
        let leaf_3 = InputLeafNode::<TestContent> {
            x_coord: 5,
            content: TestContent {
                hash: H256::default(),
                value: 4,
            },
        };

        let tree = SparseBinaryTree::new(
            vec![leaf_0, leaf_1, leaf_2, leaf_3],
            height,
            &get_padding_function(),
        )
        .expect("Tree construction should not have produced an error");

        (tree, height)
    }
}
