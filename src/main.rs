use std::str::FromStr;

use dapol::{NdmSmt, User, UserId, D256};

use core::fmt::Debug;
use dapol::{
    utils::get_secret, Dapol, DapolNode, RangeProofPadding, RangeProofSplitting, RangeProvable,
    RangeVerifiable,
};
use digest::Digest;
use rand::{distributions::Uniform, thread_rng, Rng};
use smtree::{
    index::TreeIndex,
    traits::{ProofExtractable, Rand, Serializable, TypeName},
};
use std::time::Duration;

fn main() {
    old();
}

fn new() {
    println!("new");

    let tree_height = 32;
    let num_leaves: usize = 2usize.pow(20);
    let items = build_item_list(num_leaves, tree_height);
    let users: Vec<User> = items
        .iter()
        .map(|item| User {
            id: UserId::from_str("whatever").unwrap(),
            liability: item.1.get_value(),
        })
        .collect();

    let master_secret: D256 = D256::from(3u64);
    let salt_b: D256 = D256::from(5u64);
    let salt_s: D256 = D256::from(7u64);

    let ndsmt = NdmSmt::new(master_secret, salt_b, salt_s, tree_height as u8, users).unwrap();

    // let proof = ndsmt.generate_inclusion_proof(&UserId::from_str("user1 ID").unwrap()).unwrap();
    // println!("{:?}", proof);
}

fn old() {
    println!("old");
    let num_leaves: usize = 2usize.pow(20);

    // bench tree height = 32
    let tree_height = 32;
    let items = build_item_list(num_leaves, tree_height);
    // we bench range proof padding only because building a tree does not depend on
    // the type of range proof we do
    build_dapol_tree::<blake3::Hasher, RangeProofPadding>(&items, tree_height);
}

fn build_dapol_tree<D, R>(items: &[(TreeIndex, DapolNode<D>)], tree_height: usize) -> Dapol<D, R>
where
    D: Digest + Default + Clone + TypeName + Debug,
    R: Clone + Serializable + RangeProvable + RangeVerifiable + TypeName,
{
    let secret = get_secret();
    let mut dapol = Dapol::<D, R>::new_blank(tree_height, tree_height);
    dapol.build(&items, &secret);
    dapol
}

fn build_item_list(
    num_leaves: usize,
    tree_height: usize,
) -> Vec<(TreeIndex, DapolNode<blake3::Hasher>)> {
    let mut result = Vec::new();
    let mut value = DapolNode::<blake3::Hasher>::default();
    let stride = 2usize.pow(tree_height as u32) / num_leaves;
    for i in 0..num_leaves {
        let idx = TreeIndex::from_u64(tree_height, (i * stride) as u64);
        value.randomize();
        result.push((idx, value.clone()));
    }

    result.sort_by_key(|(index, _)| *index);
    result
}
