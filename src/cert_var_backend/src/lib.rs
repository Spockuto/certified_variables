use candid::CandidType;
use ic_certified_map::HashTree;
use ic_certified_map::{leaf_hash, AsHashTree, Hash, RbTree};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::cell::Cell;
use std::cell::RefCell;

#[derive(CandidType, Serialize, Deserialize, Clone)]
struct User {
    name: String,
    age: u8,
}

impl AsHashTree for User {
    fn root_hash(&self) -> Hash {
        let user_serialized = serde_cbor::to_vec(&self).unwrap();
        leaf_hash(&user_serialized[..])
    }
    fn as_hash_tree(&self) -> HashTree<'_> {
        HashTree::Leaf(Cow::from(serde_cbor::to_vec(&self).unwrap()))
    }
}

#[derive(CandidType)]
struct CertifiedUser {
    user: User,
    certificate: Vec<u8>,
    witness: Vec<u8>,
}

thread_local! {
    static INDEX : Cell<u64> = Cell::new(0);
    static TREE: RefCell<RbTree<&'static str, RbTree<[u8; 8], User>>> = RefCell::new(RbTree::new());
}

#[ic_cdk::update]
fn set_user(user: User) -> u64 {
    let index = INDEX.with(|index| {
        let count = index.get() + 1;
        index.set(count);
        count
    });

    TREE.with_borrow_mut(|tree| {
        match tree.get(b"user") {
            Some(_) => {
                tree.modify(b"user", |inner| {
                    inner.insert(index.to_be_bytes(), user);
                });
            }
            None => {
                let mut inner = RbTree::new();
                inner.insert(index.to_be_bytes(), user);
                tree.insert("user", inner);
            }
        }
        ic_cdk::api::set_certified_data(&tree.root_hash());
    });
    index
}

#[ic_cdk::query]
fn get_user(index: u64) -> CertifiedUser {
    let certificate = ic_cdk::api::data_certificate().expect("No data certificate available");

    let user = TREE.with_borrow_mut(|tree| {
        if let Some(inner) = tree.get(b"user") {
            let user = inner.get(&index.to_be_bytes()[..]).expect("User not found");
            user.to_owned()
        } else {
            panic!("Tree isn't initialized");
        }
    });

    let witness = TREE.with(|tree| {
        let tree = tree.borrow();
        let mut witness = vec![];
        let mut witness_serializer = serde_cbor::Serializer::new(&mut witness);
        let _ = witness_serializer.self_describe();
        tree.nested_witness(b"user", |inner| inner.witness(&index.to_be_bytes()[..]))
            .serialize(&mut witness_serializer)
            .unwrap();
        witness
    });

    CertifiedUser {
        user,
        certificate,
        witness,
    }
}
