use candid::IDLArgs;
use candid::Principal;
use candid::{CandidType, Decode, Deserialize};
use candid_parser::parse_idl_args;
use ic_certificate_verification::validate_certificate_time;
use ic_certificate_verification::VerifyCertificate;
use ic_certification::hash_tree::leaf_hash;
use ic_certification::hash_tree::HashTree;
use ic_certification::{Certificate, LookupResult};
use serde_cbor::Deserializer;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(CandidType, Deserialize, Debug)]
struct CertifiedCounter {
    count: i32,
    certificate: Vec<u8>,
    witness: Vec<u8>,
}

fn main() {
    let cert = std::env::args().nth(1).expect("No candid payload given");

    let root_key: Vec<u8> = vec![
        48, 129, 130, 48, 29, 6, 13, 43, 6, 1, 4, 1, 130, 220, 124, 5, 3, 1, 2, 1, 6, 12, 43, 6, 1,
        4, 1, 130, 220, 124, 5, 3, 2, 1, 3, 97, 0, 174, 5, 192, 215, 239, 209, 220, 182, 216, 58,
        135, 48, 86, 43, 210, 140, 35, 193, 160, 171, 213, 193, 200, 64, 110, 80, 8, 244, 141, 252,
        88, 82, 134, 87, 94, 165, 148, 93, 76, 163, 21, 221, 249, 252, 171, 157, 206, 40, 19, 158,
        123, 89, 232, 72, 19, 167, 120, 24, 105, 3, 193, 107, 12, 10, 253, 139, 116, 169, 139, 32,
        123, 229, 200, 86, 234, 52, 253, 36, 38, 246, 130, 167, 12, 165, 151, 189, 72, 4, 124, 157,
        74, 43, 24, 154, 227, 199,
    ];

    let canister_id = Principal::from_text("a3shf-5eaaa-aaaaa-qaafa-cai").unwrap();
    
    const MAX_CERT_TIME_OFFSET_NS: u128 = 300_000_000_000; // 5 min

    let args: IDLArgs = parse_idl_args(&cert).unwrap();
    let encoded: Vec<u8> = args.to_bytes().unwrap();
    let cert_decoded = Decode!(&encoded[..], CertifiedCounter).unwrap();

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
    println!("Time verification result {:?}", time_verification_result);

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
        "Witness roothash mataches certified data: {:?} ",
        witness_digest == cert_var
    );

    let witness_lookup: [u8; 32] = match witness_decoded.lookup_path(["counter".as_bytes()]) {
        LookupResult::Found(result) => result.try_into().unwrap(),
        _ => panic!("Key counter not found"),
    };

    println!(
        "Witness data matches count value: {:?}",
        witness_lookup == leaf_hash(&cert_decoded.count.to_be_bytes())
    );
}
