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
use serde_cbor::Deserializer;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(CandidType, Deserialize, Debug, PartialEq, Eq, Arbitrary)]
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

static URL: &str = "http://localhost:42143";
static CANISTER: &str = "a3shf-5eaaa-aaaaa-qaafa-cai";
const MAX_CERT_TIME_OFFSET_NS: u128 = 300_000_000_000; // 5 min
const MAX_CALLS: usize = 10;

#[tokio::main]
async fn main() {
    let mut rng = rand::thread_rng();

    let agent = Agent::builder()
        .with_url(URL)
        .with_identity(AnonymousIdentity)
        .with_verify_query_signatures(true)
        .build()
        .expect("Unable to create agent");

    // This should be done only in demo environments.
    // When interacting with mainnet, hardcode the root_key.
    agent
        .fetch_root_key()
        .await
        .expect("Unable to fetch root key");
    let root_key = agent.read_root_key();

    let canister_id = Principal::from_text(CANISTER).unwrap();

    // ==== START of canister data setup
    // Make MAX_CALLS to set_user
    let mut get_user_calls = Vec::new();
    for _ in 0..MAX_CALLS {
        let bytes: [u8; 16] = rng.gen();
        let mut u = Unstructured::new(&bytes[..]);
        let temp_user = User::arbitrary(&mut u).unwrap();

        println!("Calling set_user with {:?}", temp_user);
        let response = agent
            .update(&canister_id, "set_user")
            .with_effective_canister_id(canister_id)
            .with_arg(Encode!(&temp_user).unwrap())
            .call_and_wait();
        get_user_calls.push(response);
    }
    let results: Vec<u64> = join_all(get_user_calls)
        .await
        .into_iter()
        .map(|result| {
            Decode!(
                result
                    .expect("Unable to call query call set_user")
                    .as_slice(),
                u64
            )
            .unwrap()
        })
        .collect();

    // From response indexes, chose a random index for get_user
    let index: usize = rng.gen();
    let index: u64 = *results.get(index % MAX_CALLS).unwrap();
    // ==== END of canister data setup

    println!("Fetching index {:?}", index);

    let query_response = agent
        .query(&canister_id, "get_user")
        .with_effective_canister_id(canister_id)
        .with_arg(Encode!(&index).unwrap())
        .call()
        .await
        .expect("Unable to call query call get_user");

    let certified_user = Decode!(&query_response, CertifiedUser).unwrap();

    let mut deserializer = Deserializer::from_slice(&certified_user.certificate);
    let certificate: Certificate = serde::de::Deserialize::deserialize(&mut deserializer).unwrap();

    let start = SystemTime::now();
    let current_time = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_nanos();

    // Step 1: Check if signature in the certificate matches
    // root_hash of the tree in certificate as message and root_key as public_key
    let verification_result = certificate.verify(canister_id.as_slice(), &root_key[..]);

    println!(
        "Step 1: Digest match & Signature verification: {:?}",
        verification_result
    );

    // Step 2: Check if the response is not stale with the given time offset MAX_CERT_TIME_OFFSET_NS.
    let time_verification_result =
        validate_certificate_time(&certificate, &current_time, &MAX_CERT_TIME_OFFSET_NS);

    println!("Step 2: Time skew: {:?}", time_verification_result);

    // Step 3: Check if witness root_hash matches the certified_data
    let lookup_result =
        certificate
            .tree
            .lookup_path([b"canister", canister_id.as_slice(), b"certified_data"]);

    let certified_data: [u8; 32] = match lookup_result {
        LookupResult::Found(result) => result.try_into().unwrap(),
        _ => panic!("Certified data not found"),
    };

    let mut deserializer = Deserializer::from_slice(&certified_user.witness);
    let witness_decoded: HashTree<Vec<u8>> =
        serde::de::Deserialize::deserialize(&mut deserializer).unwrap();
    let witness_digest = witness_decoded.digest();

    println!(
        "Step 3: Witness digest mataches certified data: {:?} ",
        witness_digest == certified_data
    );

    // Step 4: Check if the query parameters are in the witness
    let witness_lookup: User =
        match witness_decoded.lookup_path([b"user", &index.to_be_bytes()[..]]) {
            LookupResult::Found(result) => serde_cbor::from_slice(result).unwrap(),
            _ => panic!("user {} not found", index),
        };

    // Step 5: Check if the data found in Witness matches the returned result from the query.
    println!(
        "Step 4 & Step 5: Witness data matches User value: {:?}",
        witness_lookup == certified_user.user
    );

    // Step 6: Return the result
    println!("Result: {:?}", certified_user.user);
}
