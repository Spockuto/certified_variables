use ic_certified_map::{RbTree, leaf_hash, Hash, AsHashTree};
use std::cell::RefCell;
use serde::ser::Serialize;
use std::cell::Cell;
use candid::CandidType;

thread_local! {
    static COUNTER: Cell<i32> = Cell::new(0);
    static TREE: RefCell<RbTree<&'static str, Hash>> = RefCell::new(RbTree::new());
}

#[ic_cdk::update]
fn inc() {
    let count = COUNTER.with(|counter| {
        let count = counter.get() + 1;
        counter.set(count);
        count
    });
    TREE.with(|tree| {
        let mut tree = tree.borrow_mut();
        tree.insert("counter", leaf_hash(&count.to_be_bytes()));
        ic_cdk::api::set_certified_data(&tree.root_hash());
    })
}

#[derive(CandidType)]
struct CertifiedCounter {
    count: i32,
    certificate: Vec<u8>,
    witness: Vec<u8>,
}

#[ic_cdk::query]
fn get() -> CertifiedCounter {
    let certificate = ic_cdk::api::data_certificate().expect("No data certificate available");
    let witness = TREE.with(|tree| {
        let tree = tree.borrow();
        let mut witness = vec![];
        let mut witness_serializer = serde_cbor::Serializer::new(&mut witness);
        let _ = witness_serializer.self_describe();
        tree.witness(b"counter").serialize(&mut witness_serializer).unwrap();
        witness
    });
    let count = COUNTER.with(|counter| counter.get());
    CertifiedCounter {
        count,
        certificate,
        witness,
    }
}