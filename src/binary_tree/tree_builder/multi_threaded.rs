//! Binary tree builder that utilizes parallelization to get the best build
//! time.
//!
//! The build algorithm starts from the root node and makes it's way down
//! to the bottom layer, splitting off a new thread at each junction.
//! A recursive function is used to do the traversal since every node above
//! the bottom layer can be viewed as the root node of a sub-tree of the main
//! tree. So every recursive iteration has an associated thread, root node that
//! needs building, and 2 child nodes that it will use to build the root node.
//! Construction of the child nodes is done using a recursive call. The base
//! case happens when a thread reaches a layer above the bottom layer, where the
//! children are the leaf nodes inputted by the original calling code.
//!
//! Because the tree is sparse not all of the paths to the bottom layer need
//! to be traversed--only those paths that will end in a bottom-layer leaf
//! node. At each junction a thread will first determine if it needs to traverse
//! either the left child, the right child or both. If both then it will spawn a
//! new thread to traverse the right child before traversing the left itself,
//! and if only left/right need to be traversed then it will do so itself
//! without spawning a new thread. Note that children that do not need traversal
//! are padding nodes, and are constructed using the closure given by the
//! calling code. Each thread uses a sorted vector of bottom-layer leaf nodes to
//! determine if a child needs traversing: the idea is that at each recursive
//! iteration the vector should contain all the leaf nodes that will live at the
//! bottom of the sub-tree (no more and no less). The first iteration will have
//! all the input leaf nodes, and will split the vector between the left & right
//! recursive calls, each of which will split the vector to their children, etc.
//!
//! Not all of the nodes in the tree are necessarily placed in the store. By
//! default only the non-padding leaf nodes and the nodes in the top half of the
//! tree are placed in the store. This can be increased using the `store_depth`
//! parameter. If `store_depth == 1` then only the root node is stored and if
//! `store_depth == n` then the root node plus the next `n-1` layers from the
//! root node down are stored. So if `store_depth == height` then all the nodes
//! are stored.

use core::fmt;
use std::fmt::Debug;
use std::ops::Range;

use log::warn;
use logging_timer::stime;

use dashmap::DashMap;
use rayon::prelude::*;
use std::sync::{Arc, Mutex};
use std::thread;

use serde::{Deserialize, Serialize};

use derive_builder::Builder;

use crate::{MaxThreadCount, MAX_HEIGHT};

use super::super::{
    Coordinate, Height, InputLeafNode, MatchedPair, Mergeable, Node, Sibling, Store,
    MIN_RECOMMENDED_SPARSITY, MIN_STORE_DEPTH,
};
use super::{BinaryTree, TreeBuildError};

const BUG: &str = "[Bug in multi-threaded builder]";

// -------------------------------------------------------------------------------------------------
// Tree build function.

/// Construct the binary tree.
///
/// The leaf node vector is cleaned in the following ways:
/// - sorted according to their x-coord
/// - all x-coord <= max
/// - checked for duplicates (duplicate if same x-coords)
#[stime("info", "MultiThreadedBuilder::{}")]
pub fn build_tree<C: fmt::Display, F>(
    height: Height,
    store_depth: u8,
    mut input_leaf_nodes: Vec<InputLeafNode<C>>,
    new_padding_node_content: F,
    max_thread_count: MaxThreadCount,
) -> Result<BinaryTree<C>, TreeBuildError>
where
    C: Debug + Clone + Mergeable + Send + Sync + 'static,
    F: Fn(&Coordinate) -> C + Send + Sync + 'static,
{
    use super::verify_no_duplicate_leaves;

    let leaf_nodes = {
        // Sort by x-coord ascending.
        input_leaf_nodes.par_sort_by(|a, b| a.x_coord.cmp(&b.x_coord));

        verify_no_duplicate_leaves(&input_leaf_nodes)?;

        // Translate InputLeafNode to Node.
        input_leaf_nodes
            .into_par_iter()
            .map(|input_node| input_node.into_node())
            .collect::<Vec<Node<C>>>()
    };

    let max_nodes = max_nodes_to_store(leaf_nodes.len() as u64, &height);
    let store = Arc::new(DashMap::<Coordinate, Node<C>>::with_capacity(
        max_nodes as usize,
    ));
    let params = RecursionParamsBuilder::default()
        .height(height)
        .store_depth(store_depth)
        .max_thread_count(max_thread_count.as_u8())
        .build();

    if height.max_bottom_layer_nodes() / leaf_nodes.len() as u64 <= MIN_RECOMMENDED_SPARSITY as u64
    {
        warn!(
            "Minimum recommended tree sparsity of {} reached, consider increasing tree height",
            MIN_RECOMMENDED_SPARSITY
        );
    }

    // Parallelized build algorithm.
    let root = build_node(
        params,
        leaf_nodes,
        Arc::new(new_padding_node_content),
        Arc::clone(&store),
    );

    store.insert(root.coord.clone(), root.clone());
    store.shrink_to_fit();

    let store = DashMapStore {
        map: Arc::into_inner(store).ok_or(TreeBuildError::StoreOwnershipFailure)?,
    };

    Ok(BinaryTree {
        root,
        store: Store::MultiThreadedStore(store),
        height,
    })
}

// -------------------------------------------------------------------------------------------------
// Store.

type Map<C> = DashMap<Coordinate, Node<C>>;

#[derive(Serialize, Deserialize)]
pub struct DashMapStore<C: fmt::Display> {
    map: Map<C>,
}

impl<C: Clone + fmt::Display> DashMapStore<C> {
    pub fn get_node(&self, coord: &Coordinate) -> Option<Node<C>> {
        self.map.get(coord).map(|n| n.clone())
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }
}

// -------------------------------------------------------------------------------------------------
// Supporting functions, structs, etc.

/// Returns the index `i` in `nodes` where `nodes[i].coord.x <= x_coord_mid`
/// but `nodes[i+1].coord.x > x_coord_mid`.
/// Requires `nodes` to be sorted according to the x-coord field.
/// If all nodes satisfy `node.coord.x <= mid` then `Full` is returned.
/// If no nodes satisfy `node.coord.x <= mid` then `Empty` is returned.
// TODO can be optimized using a binary search
fn num_nodes_left_of<C: fmt::Display>(x_coord_mid: u64, nodes: &Vec<Node<C>>) -> NumNodes {
    nodes
        .iter()
        .rposition(|leaf| leaf.coord.x <= x_coord_mid)
        .map_or(NumNodes::Empty, |index| {
            if index == nodes.len() - 1 {
                NumNodes::Full
            } else {
                NumNodes::Partial(index)
            }
        })
}

enum NumNodes {
    Full,
    Empty,
    Partial(usize),
}

impl<C: fmt::Display> Node<C> {
    /// New padding node contents are given by a closure. Why a closure? Because
    /// creating a padding node may require context outside of this scope, where
    /// type `C` is defined, for example.
    fn new_sibling_padding_node_arc<F>(&self, new_padding_node_content: Arc<F>) -> Node<C>
    where
        F: Fn(&Coordinate) -> C,
    {
        let coord = self.sibling_coord();
        let content = new_padding_node_content(&coord);
        Node { coord, content }
    }
}

impl<C: Mergeable + fmt::Display> MatchedPair<C> {
    /// Create a pair of left and right sibling nodes from only 1 node and the
    /// padding node generation function.
    ///
    /// This function is made to be used by multiple threads that share
    /// `new_padding_node_content`.
    fn from_node<F>(node: Node<C>, new_padding_node_content: Arc<F>) -> Self
    where
        C: Send + 'static,
        F: Fn(&Coordinate) -> C + Send + Sync + 'static,
    {
        let sibling = Sibling::from(node);
        match sibling {
            Sibling::Left(left) => MatchedPair::from((
                left.new_sibling_padding_node_arc(new_padding_node_content),
                left,
            )),
            Sibling::Right(right) => MatchedPair::from((
                right.new_sibling_padding_node_arc(new_padding_node_content),
                right,
            )),
        }
    }
}

// -------------------------------------------------------------------------------------------------
// Build algorithm.

/// Parameters for the recursive build function.
///
/// Every iteration of [build_node] relates to a particular layer in the tree,
/// and `y_coord` is exactly what defines this layer.
///
/// The x-coord fields relate to the bottom layer of the tree.
///
/// `x_coord_min` is the left-most x-coord of the bottom layer nodes of the
/// subtree whose root node is the current one being generated by the recursive
/// iteration. `x_coord_max` is the right-most x-coord of the bottom layer nodes
/// of the same subtree.
///
/// `x_coord_mid` is used to split the leaves into left and right vectors.
/// Nodes in the left vector have x-coord <= mid, and
/// those in the right vector have x-coord > mid.
///
/// `max_thread_count` is there to prevent more threads being spawned
/// than there are cores to execute them. If too many threads are spawned then
/// the parallelization can actually be detrimental to the run-time. Threads
#[derive(Clone, Debug, Builder)]
#[builder(build_fn(skip))]
pub struct RecursionParams {
    #[builder(setter(skip))]
    x_coord_min: u64,
    #[builder(setter(skip))]
    x_coord_mid: u64,
    #[builder(setter(skip))]
    x_coord_max: u64,
    #[builder(setter(skip))]
    y_coord: u8,
    #[builder(setter(skip))]
    thread_count: Arc<Mutex<u8>>,
    max_thread_count: u8,
    store_depth: u8,
    height: Height,
}

impl RecursionParamsBuilder {
    pub fn build(&self) -> RecursionParams {
        let height = self.height.unwrap_or(MAX_HEIGHT);

        let x_coord_min = 0;
        // x-coords start from 0, hence the `- 1`.
        let x_coord_max = height.max_bottom_layer_nodes() - 1;
        let x_coord_mid = (x_coord_min + x_coord_max) / 2;
        // y-coords also start from 0, hence the `- 1`.
        let y_coord = height.as_y_coord();

        RecursionParams {
            x_coord_min,
            x_coord_mid,
            x_coord_max,
            y_coord,
            height,
            thread_count: Arc::new(Mutex::new(1)),
            max_thread_count: self.max_thread_count.unwrap_or(1),
            store_depth: self.store_depth.unwrap_or(MIN_STORE_DEPTH),
        }
    }

    pub fn build_with_coord(&self, coord: &Coordinate) -> RecursionParams {
        let (x_coord_min, x_coord_max) = coord.subtree_x_coord_bounds();
        let x_coord_mid = (x_coord_min + x_coord_max) / 2;

        RecursionParams {
            x_coord_min,
            x_coord_mid,
            x_coord_max,
            y_coord: coord.y,
            thread_count: Arc::new(Mutex::new(1)),
            height: self.height.unwrap_or(MAX_HEIGHT),
            max_thread_count: self.max_thread_count.unwrap_or(1),
            store_depth: self.store_depth.unwrap_or(MIN_STORE_DEPTH),
        }
    }
}

/// Private functions for use within this file only.
impl RecursionParams {
    /// Convert the params for the node which is the focus of the current
    /// iteration to params for that node's left child.
    fn into_left_child(mut self) -> Self {
        self.x_coord_max = self.x_coord_mid;
        self.x_coord_mid = (self.x_coord_min + self.x_coord_max) / 2;
        self.y_coord -= 1;
        self
    }

    /// Convert the params for the node which is the focus of the current
    /// iteration to params for that node's right child.
    fn into_right_child(mut self) -> Self {
        self.x_coord_min = self.x_coord_mid + 1;
        self.x_coord_mid = (self.x_coord_min + self.x_coord_max) / 2;
        self.y_coord -= 1;
        self
    }

    /// Construct the parameters given only the height of the tree.
    ///
    /// - `x_coord_min` points to the start of the bottom layer.
    /// - `x_coord_max` points to the end of the bottom layer.
    /// - `x_coord_mid` is set to the middle of `x_coord_min` & `x_coord_max`.
    /// - `y_coord` is set to `height - 1` because the recursion starts from the
    /// root node.
    /// - `tread_count` is set to 1 (not 0) to account for the main thread.
    /// - `max_thread_count` is set based on how much [parallelism] the
    /// underlying machine is able to offer.
    /// - `store_depth` defaults to the min value.
    ///
    /// [parallelism]: std::thread::available_parallelism
    fn new_with_height(height: Height) -> Self {
        let x_coord_min = 0;
        // x-coords start from 0, hence the `- 1`.
        let x_coord_max = height.max_bottom_layer_nodes() - 1;
        let x_coord_mid = (x_coord_min + x_coord_max) / 2;
        // y-coords also start from 0, hence the `- 1`.
        let y_coord = height.as_y_coord();

        RecursionParams {
            x_coord_min,
            x_coord_mid,
            x_coord_max,
            y_coord,
            // TODO need to unit test that this number matches actual thread count
            thread_count: Arc::new(Mutex::new(1)),
            max_thread_count: 1,
            store_depth: MIN_STORE_DEPTH,
            height,
        }
    }

    pub fn x_coord_range(&self) -> Range<u64> {
        self.x_coord_min..self.x_coord_max + 1
    }
}

/// Recursive, multi-threaded function for building a node by exploring the tree
/// from top-to-bottom. See docs at the top of the file for an explanation of
/// how it works.
///
/// `x_coord_min` and `x_coord_max` are the bounds of the sub-tree with respect
/// to the x-coords of the bottom layer of the main tree. Thus
/// `x_coord_max - x_coord_min - 1` will always be a power of 2. Example: if you
/// have a tree with a height of 5 then its bottom layer nodes will have
/// x-coord ranging from 0 to 15 (min & max), and the sub-tree whose root node
/// is the right child of the main tree's root node will have leaf nodes whose
/// x-coords range from 8 to 15 (min & max).
///
/// `height` is a natural number (1 onwards), while `y` is a counting number (0
/// onwards). `height` represents the height of the whole tree, while `y` is
/// is the height of the sub-tree associated with a specific recursive
/// iteration.
///
/// `leaves` must be sorted according to the nodes' x-coords. There is no panic
/// protection that checks for this.
///
/// Node length should never exceed the max number of bottom-layer nodes for a
/// sub-tree with height `y` since this means there are more nodes than can fit
/// into the sub-tree. Similarly, node length should never reach 0 since that
/// means we did not need do any work for this sub-tree but we entered the
/// function anyway. If either case is reached then either there is a bug in the
/// original calling code or there is a bug in the splitting algorithm in this
/// function. There is no recovery from these 2 states so we panic.
pub fn build_node<C: fmt::Display, F>(
    params: RecursionParams,
    mut leaves: Vec<Node<C>>,
    new_padding_node_content: Arc<F>,
    map: Arc<Map<C>>,
) -> Node<C>
where
    C: Debug + Clone + Mergeable + Send + Sync + 'static,
    F: Fn(&Coordinate) -> C + Send + Sync + 'static,
{
    {
        let max_nodes = Height::from_y_coord(params.y_coord).max_bottom_layer_nodes();
        assert!(
            leaves.len() <= max_nodes as usize,
            "{} Leaf node count ({}) exceeds layer max node number ({})",
            BUG,
            leaves.len(),
            max_nodes
        );

        assert_ne!(leaves.len(), 0, "{} Number of leaf nodes cannot be 0", BUG);

        assert!(
            params.x_coord_min % 2 == 0,
            "{} x_coord_min ({}) must be a multiple of 2 or 0",
            BUG,
            params.x_coord_min
        );

        assert!(
            params.x_coord_max % 2 == 1,
            "{} x_coord_max ({}) must not be a multiple of 2",
            BUG,
            params.x_coord_max
        );

        let v = params.x_coord_max - params.x_coord_min + 1;
        assert!(
            (v & (v - 1)) == 0,
            "{} x_coord_max - x_coord_min + 1 ({}) must be a power of 2",
            BUG,
            v
        );
    }

    // Base case: reached the 2nd-to-bottom layer.
    // There are either 2 or 1 leaves left (which is checked above).
    if params.y_coord == 1 {
        let pair = if leaves.len() == 2 {
            let right = leaves.pop().unwrap();
            let left = leaves.pop().unwrap();

            map.insert(left.coord.clone(), left.clone());
            map.insert(right.coord.clone(), right.clone());

            MatchedPair::from((left, right))
        } else {
            let node = leaves.pop().unwrap();
            let sibling = node.new_sibling_padding_node_arc(new_padding_node_content);

            map.insert(node.coord.clone(), node.clone());

            // Only store the padding node if the store depth is at maximum.
            if params.store_depth == params.height.as_u8() {
                map.insert(sibling.coord.clone(), sibling.clone());
            }

            MatchedPair::from((node, sibling))
        };

        return pair.merge();
    }

    // NOTE this includes the root node.
    let within_store_depth_for_children =
        params.y_coord > params.height.as_u8() - params.store_depth;

    let pair = match num_nodes_left_of(params.x_coord_mid, &leaves) {
        NumNodes::Partial(index) => {
            let right_leaves = leaves.split_off(index + 1);
            let left_leaves = leaves;

            let new_padding_node_content_ref = Arc::clone(&new_padding_node_content);

            // Check if the thread pool has 1 to spare.
            // We must atomically set the boolean.

            let mut spawn_thread = false;
            {
                let mut thread_count = params.thread_count.lock().unwrap();
                if *thread_count < params.max_thread_count {
                    *thread_count += 1;
                    spawn_thread = true;
                }
            }

            // Split off a thread to build the right child, but only do this if the thread
            // count is less than the max allowed.
            if spawn_thread {
                let params_clone = params.clone();
                let map_ref = Arc::clone(&map);

                let right_handler = thread::spawn(move || -> Node<C> {
                    build_node(
                        params_clone.into_right_child(),
                        right_leaves,
                        new_padding_node_content_ref,
                        map_ref,
                    )
                });

                let left = build_node(
                    params.clone().into_left_child(),
                    left_leaves,
                    new_padding_node_content,
                    Arc::clone(&map),
                );

                // If there is a problem joining onto the thread then there is no way to recover
                // so panic.
                let right = right_handler
                    .join()
                    .unwrap_or_else(|_| panic!("{} Couldn't join on the associated thread", BUG));

                // Give back to the thread pool again.
                {
                    let mut thread_count = params.thread_count.lock().unwrap();
                    if *thread_count > 1 {
                        *thread_count -= 1;
                    }
                }

                MatchedPair::from((left, right))
            } else {
                let right = build_node(
                    params.clone().into_right_child(),
                    right_leaves,
                    new_padding_node_content_ref,
                    Arc::clone(&map),
                );

                let left = build_node(
                    params.into_left_child(),
                    left_leaves,
                    new_padding_node_content,
                    Arc::clone(&map),
                );

                MatchedPair::from((left, right))
            }
        }
        NumNodes::Full => {
            // Go down left child only (there are no leaves living on the right side).
            let left = build_node(
                params.into_left_child(),
                leaves,
                new_padding_node_content.clone(),
                Arc::clone(&map),
            );
            let right = left.new_sibling_padding_node_arc(new_padding_node_content);
            MatchedPair::from((left, right))
        }
        NumNodes::Empty => {
            // Go down right child only (there are no leaves living on the left side).
            let right = build_node(
                params.into_right_child(),
                leaves,
                new_padding_node_content.clone(),
                Arc::clone(&map),
            );
            let left = right.new_sibling_padding_node_arc(new_padding_node_content);
            MatchedPair::from((left, right))
        }
    };

    if within_store_depth_for_children {
        map.insert(pair.left.coord.clone(), pair.left.clone());
        map.insert(pair.right.coord.clone(), pair.right.clone());
    }

    pair.merge()
}

// TODO this does not work if store depth is not 100%
/// The maximum number of nodes that would need to be stored.
///
/// $$2n(h-\text{log}_2(n))-1$$
///
/// If we convert the result to a u64 then we should round up since we are
/// trying to get an upper bound. Exactly the same result can be achieved
/// by removing the -1 and flooring the result:
///
/// $$\text{floor}(2n(h-\text{log}_2(n)))$$
fn max_nodes_to_store(num_leaf_nodes: u64, height: &Height) -> u64 {
    let n = num_leaf_nodes as f64;
    let k = n.log2();
    let h = height.as_f64();

    (2. * n * (h - k)) as u64
}

// -------------------------------------------------------------------------------------------------
// Unit tests.

// TODO check all leaf nodes are in the store, and that the desired level of
// nodes is in the store TODO check certain number of leaf nodes are in the tree
// TODO recursive function err - num leaf nodes exceeds max
// TODO recursive function err - empty leaf nodes
// TODO recursive function err - NOT x-coord min multiple of 2 or 0
// TODO recursive function err - NOT x-coord max multiple of 2
// TODO recursive function err - max - min must be power of 2

#[cfg(any(test, feature = "fuzzing"))]
pub(crate) mod tests {
    use std::str::FromStr;

    use super::super::*;
    use super::*;
    use crate::binary_tree::utils::test_utils::{
        full_bottom_layer, generate_padding_closure, random_leaf_nodes, single_leaf, sparse_leaves,
        TestContent,
    };
    use crate::utils::test_utils::{assert_err, assert_err_simple};

    use primitive_types::H256;
    use rand::{thread_rng, Rng};

    #[test]
    fn err_when_parent_builder_height_not_set() {
        let height = Height::expect_from(4);
        let leaf_nodes = full_bottom_layer(&height);
        let res = BinaryTreeBuilder::new()
            .with_leaf_nodes(leaf_nodes)
            .build_using_multi_threaded_algorithm(generate_padding_closure());

        // cannot use assert_err because it requires Func to have the Debug trait
        assert_err_simple!(res, Err(TreeBuildError::NoHeightProvided));
    }

    #[test]
    fn err_when_parent_builder_leaf_nodes_not_set() {
        let height = Height::expect_from(4);
        let res = BinaryTreeBuilder::new()
            .with_height(height)
            .build_using_multi_threaded_algorithm(generate_padding_closure());

        // cannot use assert_err because it requires Func to have the Debug trait
        assert_err_simple!(res, Err(TreeBuildError::NoLeafNodesProvided));
    }

    #[test]
    fn err_for_empty_leaves() {
        let height = Height::expect_from(5);
        let res = BinaryTreeBuilder::<TestContent>::new()
            .with_height(height)
            .with_leaf_nodes(Vec::<InputLeafNode<TestContent>>::new())
            .build_using_multi_threaded_algorithm(generate_padding_closure());

        assert_err!(res, Err(TreeBuildError::EmptyLeaves));
    }

    #[test]
    fn err_for_too_many_leaves_with_height_first() {
        let height = Height::expect_from(8u8);
        let max_nodes = height.max_bottom_layer_nodes();
        let mut leaf_nodes = full_bottom_layer(&height);

        leaf_nodes.push(InputLeafNode::<TestContent> {
            x_coord: max_nodes + 1,
            content: TestContent {
                hash: H256::random(),
                value: thread_rng().gen(),
            },
        });

        let res = BinaryTreeBuilder::new()
            .with_height(height)
            .with_leaf_nodes(leaf_nodes)
            .build_using_multi_threaded_algorithm(generate_padding_closure());

        assert_err!(
            res,
            Err(TreeBuildError::TooManyLeaves {
                // TODO does assert_err work for these values? If we change the values does the test
                // pass?
                given: leaf_nodes,
                max: max_nodes,
            })
        );
    }

    #[test]
    fn err_for_duplicate_leaves() {
        let height = Height::expect_from(4);
        let mut leaf_nodes = sparse_leaves(&height);
        leaf_nodes.push(single_leaf(leaf_nodes.get(0).unwrap().x_coord));

        let res = BinaryTreeBuilder::new()
            .with_height(height)
            .with_leaf_nodes(leaf_nodes)
            .build_using_multi_threaded_algorithm(generate_padding_closure());

        // cannot use assert_err because it requires Func to have the Debug trait
        assert_err_simple!(res, Err(TreeBuildError::DuplicateLeaves));
    }

    #[test]
    fn err_when_x_coord_greater_than_max() {
        let height = Height::expect_from(4);
        let leaf_node = single_leaf(height.max_bottom_layer_nodes() + 1);

        let res = BinaryTreeBuilder::new()
            .with_height(height)
            .with_leaf_nodes(vec![leaf_node])
            .build_using_multi_threaded_algorithm(generate_padding_closure());

        // cannot use assert_err because it requires Func to have the Debug trait
        assert_err_simple!(res, Err(TreeBuildError::InvalidXCoord));
    }

    // tests that the sorting functionality works
    #[test]
    fn different_ordering_of_leaf_nodes_gives_same_root() {
        use rand::seq::SliceRandom;
        use rand::thread_rng;

        let height = Height::expect_from(4);
        let mut leaf_nodes = sparse_leaves(&height);

        let tree = BinaryTreeBuilder::new()
            .with_height(height)
            .with_leaf_nodes(leaf_nodes.clone())
            .build_using_multi_threaded_algorithm(generate_padding_closure())
            .unwrap();
        let root = tree.root();

        leaf_nodes.shuffle(&mut thread_rng());

        let tree = BinaryTreeBuilder::new()
            .with_height(height)
            .with_leaf_nodes(leaf_nodes)
            .build_using_multi_threaded_algorithm(generate_padding_closure())
            .unwrap();

        assert_eq!(root, tree.root());
    }

    #[test]
    fn bottom_layer_leaf_nodes_all_present_in_store() {
        let height = Height::expect_from(5);
        let leaf_nodes = sparse_leaves(&height);

        let tree = BinaryTreeBuilder::new()
            .with_height(height)
            .with_leaf_nodes(leaf_nodes.clone())
            .build_using_multi_threaded_algorithm(generate_padding_closure())
            .unwrap();

        for leaf in leaf_nodes {
            tree.get_leaf_node(leaf.x_coord).unwrap_or_else(|| {
                panic!(
                    "Leaf node at x-coord {} is not present in the store",
                    leaf.x_coord
                )
            });
        }
    }

    #[test]
    fn expected_internal_nodes_are_in_the_store_for_default_store_depth() {
        let height = Height::expect_from(8);
        let leaf_nodes = full_bottom_layer(&height);

        let tree = BinaryTreeBuilder::new()
            .with_height(height)
            .with_leaf_nodes(leaf_nodes.clone())
            .build_using_multi_threaded_algorithm(generate_padding_closure())
            .unwrap();

        let middle_layer = height.as_u8() / 2;
        let layer_below_root = height.as_u8() - 1;

        // These nodes should be in the store.
        for y in middle_layer..layer_below_root {
            for x in 0..2u64.pow((height.as_u8() - y - 1) as u32) {
                let coord = Coordinate { x, y };
                tree.store
                    .get_node(&coord)
                    .unwrap_or_else(|| panic!("{:?} was expected to be in the store", coord));
            }
        }

        // These nodes should not be in the store.
        // Why 1 and not 0? Because leaf nodes are checked in another test.
        for y in 1..middle_layer {
            for x in 0..2u64.pow((height.as_u8() - y - 1) as u32) {
                let coord = Coordinate { x, y };
                if tree.store.get_node(&coord).is_some() {
                    panic!("{:?} was expected to not be in the store", coord);
                }
            }
        }
    }

    #[test]
    fn expected_internal_nodes_are_in_the_store_for_custom_store_depth() {
        let height = Height::expect_from(8);
        let leaf_nodes = full_bottom_layer(&height);
        // TODO fuzz on this store depth
        let store_depth = 1;

        let tree = BinaryTreeBuilder::new()
            .with_height(height)
            .with_leaf_nodes(leaf_nodes.clone())
            .with_store_depth(store_depth)
            .build_using_multi_threaded_algorithm(generate_padding_closure())
            .unwrap();

        let layer_below_root = height.as_u8() - 1;

        // Only the leaf nodes should be in the store.
        for x in 0..2u64.pow((height.as_u8() - 1) as u32) {
            let coord = Coordinate { x, y: 0 };
            tree.store
                .get_node(&coord)
                .unwrap_or_else(|| panic!("{:?} was expected to be in the store", coord));
        }

        // All internal nodes should not be in the store.
        for y in 1..layer_below_root {
            for x in 0..2u64.pow((height.as_u8() - y - 1) as u32) {
                let coord = Coordinate { x, y };
                if tree.store.get_node(&coord).is_some() {
                    panic!("{:?} was expected to not be in the store", coord);
                }
            }
        }
    }

    #[cfg(fuzzing)]
    pub fn fuzz_max_nodes_to_store(randomness: u64) {
        // Bound the randomness.
        let height = {
            let max_height = 6;
            let min_height = crate::MIN_HEIGHT.as_u8();
            Height::from((randomness as u8 % (max_height - min_height)) + min_height)
        };
        let num_leaf_nodes = {
            let upper_bound = height.max_bottom_layer_nodes();
            let lower_bound = 1;
            lower_bound + (randomness % (upper_bound - lower_bound))
        };

        // Value to check.
        let max_nodes = max_nodes_to_store(num_leaf_nodes, &height);

        // Max store depth.
        let store_depth = height.as_u8();
        let leaf_nodes = random_leaf_nodes(num_leaf_nodes, &height, randomness);

        let tree = BinaryTreeBuilder::new()
            .with_height(height)
            .with_leaf_nodes(leaf_nodes)
            .with_store_depth(store_depth)
            .build_using_multi_threaded_algorithm(generate_padding_closure())
            .unwrap();

        assert!(tree.store.len() < max_nodes as usize);
    }

    #[test]
    fn max_nodes_to_store_equality() {
        // Got this by using the fuzzer and setting fuzz_max_nodes_to_store to
        // assert strictly less than.
        let seed = 16488547165734;

        let height = Height::expect_from(6);
        let num_leaf_nodes = 3;
        let store_depth = height.as_u8();
        let leaf_nodes = random_leaf_nodes(num_leaf_nodes, &height, seed);
        let expected_number_of_nodes_in_store = max_nodes_to_store(num_leaf_nodes, &height) - 1;

        let tree = BinaryTreeBuilder::new()
            .with_height(height)
            .with_leaf_nodes(leaf_nodes)
            .with_store_depth(store_depth)
            .build_using_multi_threaded_algorithm(generate_padding_closure())
            .unwrap();

        assert_eq!(tree.store.len(), expected_number_of_nodes_in_store as usize);
    }
}
