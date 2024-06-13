use arbitrary::{Arbitrary, Unstructured};
use candid::Encode;
use candid::Principal;
use candid::{CandidType, Decode, Deserialize};
use futures::future::join_all;
use ic_agent::identity::AnonymousIdentity;
use ic_agent::Agent;
use ic_certificate_verification::validate_certificate_time;
use ic_certificate_verification::VerifyCertificate;
use ic_certification::hash_tree::HashTree;
use ic_certification::{Certificate, LookupResult};
use rand::prelude::*;
use serde::Serialize;
use serde_cbor::Deserializer;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Arbitrary)]
struct User {
    name: String,
    age: u8,
}

#[derive(CandidType, Deserialize)]
struct CertifiedUser {
    user: User,
    certificate: Vec<u8>,
    witness: Vec<u8>,
}

static URL: &str = "http://localhost:35473";
static CANISTER: &str = "a3shf-5eaaa-aaaaa-qaafa-cai";
const MAX_CERT_TIME_OFFSET_NS: u128 = 300_000_000_000; // 5 min

#[tokio::main]
async fn main() {
    let mut rng = rand::thread_rng();

    let agent = Agent::builder()
        .with_url(URL)
        .with_identity(AnonymousIdentity)
        .build()
        .expect("Unable to create agent");

    // Only for demo purposes. Hard code when using for IC
    agent
        .fetch_root_key()
        .await
        .expect("Unable to fetch root key");
    let root_key = agent.read_root_key();

    let canister_id = Principal::from_text(CANISTER).unwrap();

    // Make 5 random update calls for set_user
    let mut inc_calls = Vec::new();
    for i in 0..5 {
        let bytes: [u8; 16] = rng.gen();
        let mut u = Unstructured::new(&bytes[..]);
        let temp_user = User::arbitrary(&mut u).unwrap();

        println!("Calling set_user at {:?} with {:?}", i, temp_user);
        let response = agent
            .update(&canister_id, "set_user")
            .with_effective_canister_id(canister_id)
            .with_arg(Encode!(&temp_user).unwrap())
            .call_and_wait();
        inc_calls.push(response);
    }
    join_all(inc_calls).await;

    // call a random index with get_user
    let index: u64 = rng.gen();
    let index: u64 = index % 5 + 1;

    let query_response = agent
        .query(&canister_id, "get_user")
        .with_effective_canister_id(canister_id)
        .with_arg(Encode!(&index).unwrap())
        .call()
        .await
        .expect("Unable to call query call get_user");
    let cert_decoded = Decode!(&query_response, CertifiedUser).unwrap();

    let mut deserializer = Deserializer::from_slice(&cert_decoded.certificate);
    let certificate: Certificate = serde::de::Deserialize::deserialize(&mut deserializer).unwrap();

    let start = SystemTime::now();
    let current_time = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_nanos();

    // Digest equality and signature verification are done here
    let verification_result = certificate.verify(canister_id.as_slice(), &root_key[..]);
    // Time skew is verified here
    let time_verification_result =
        validate_certificate_time(&certificate, &current_time, &MAX_CERT_TIME_OFFSET_NS);

    println!(
        "Verification result (Digest match & Signature verification): {:?}",
        verification_result
    );
    println!("Time skew: {:?}", time_verification_result);

    // Check if witness is in the tree
    let lookup_result = certificate.tree.lookup_path([
        "canister".as_bytes(),
        canister_id.as_slice(),
        "certified_data".as_bytes(),
    ]);

    let mut deserializer = Deserializer::from_slice(&cert_decoded.witness);
    let witness_decoded: HashTree<Vec<u8>> =
        serde::de::Deserialize::deserialize(&mut deserializer).unwrap();

    let witness_digest = witness_decoded.digest();

    let cert_var: [u8; 32] = match lookup_result {
        LookupResult::Found(result) => result.try_into().unwrap(),
        _ => panic!("Certified data not found"),
    };

    println!(
        "Witness root_hash mataches certified data: {:?} ",
        witness_digest == cert_var
    );

    let witness_lookup: User =
        match witness_decoded.lookup_path([b"user", &index.to_be_bytes()[..]]) {
            LookupResult::Found(result) => serde_cbor::from_slice(result).unwrap(),
            _ => panic!("user {} not found", index),
        };

    println!(
        "Witness data matches User value: {:?}",
        witness_lookup == cert_decoded.user
    );
    println!("Result: {:?}", cert_decoded.user);
}
