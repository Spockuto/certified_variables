import pkg from "@dfinity/agent";
const {
    Actor,
    HttpAgent,
    Certificate,
    blsVerify,
    Cbor,
    reconstruct,
    lookup_path,
} = pkg;
import {
    IDL
} from "@dfinity/candid";
import {
    Principal
} from "@dfinity/principal";
import fetch from "isomorphic-fetch";
import assert from "node:assert/strict";

const idlFactory = ({
    IDL
}) => {
    const User = IDL.Record({
        age: IDL.Nat8,
        name: IDL.Text
    });
    const CertifiedUser = IDL.Record({
        certificate: IDL.Vec(IDL.Nat8),
        user: User,
        witness: IDL.Vec(IDL.Nat8),
    });
    return IDL.Service({
        get_user: IDL.Func([IDL.Nat64], [CertifiedUser], ["query"]),
        set_user: IDL.Func([User], [IDL.Nat64], []),
    });
};

const canisterId = Principal.fromText("ajuq4-ruaaa-aaaaa-qaaga-cai");
const host = "http://localhost:42783";

start().await;

async function start() {
    const agent = new HttpAgent({
        fetch,
        host
    });
    await agent.fetchRootKey();

    const rootKey = agent.rootKey.buffer;
    let dummyUser = {
        name: "test_user",
        age: 21
    };

    const actor = Actor.createActor(idlFactory, {
        agent,
        canisterId,
    });

    let index = await actor.set_user(dummyUser);
    let certifiedUser = await actor.get_user(index);

    await verifyCertificate(certifiedUser, index, rootKey, canisterId);
}

async function verifyCertificate(certifiedUser, index, rootKey, canisterId) {
    const certificate = certifiedUser.certificate.buffer;
    const witness = certifiedUser.witness.buffer;
    const user = certifiedUser.user;

    const cert = new Certificate(certificate, rootKey, canisterId, blsVerify);

    // Step 1: Check if signature in the certificate can be validated with the 
    // root_hash of the tree in certificate as message and root_key as public_key
    await cert.verify();
    console.log("Certificate verification succeeded");

    // Step 2: Check if the response is not stale with the given time offset of 5m.
    const te = new TextEncoder();
    const pathTime = [te.encode("time")];
    const rawTime = cert.lookup(pathTime).value;
    console.log("Time skew: ", verifyTime(rawTime));

    // Step 3: Check if witness root_hash matches the certified_data
    const pathData = [
        te.encode("canister"),
        canisterId.toUint8Array(),
        te.encode("certified_data"),
    ];

    const certifiedData = cert.lookup(pathData).value;
    let witnessTree = Cbor.decode(witness);
    let witnessRootHash = await reconstruct(witnessTree);
    console.log(
        "Verify CertifiedData matches witness root_hash: ",
        certifiedData.buffer === witnessRootHash.buffer
    );

    // Step 4: Check if the query parameters are in the witness
    const query_params = [te.encode("user"), bigEndian(index).buffer];
    const witnessData = Cbor.decode(lookup_path(query_params, witnessTree).value);
    console.log("Witness data: ", witnessData);

    // Step 5: Check if the data found in Witness matches the returned result from the query.
    assert.deepStrictEqual(witnessData, user, "Value matches response data");

    // Step 6: Return the result
    return user
}

function verifyTime(rawTime) {
    const idlMessage = new Uint8Array([
        ...new TextEncoder().encode("DIDL\x00\x01\x7d"),
        ...new Uint8Array(rawTime),
    ]);
    const decodedTime = IDL.decode([IDL.Nat], idlMessage)[0];
    const time = Number(decodedTime) / 1e9;
    const now = Date.now() / 1000;
    const diff = Math.abs(time - now);
    if (diff > 5) {
        return false;
    }
    return true;
}

function bigEndian(n) {
    let buf = new Uint8Array(8);

    for (let i = 7; i >= 0; i--) {
        buf[i] = Number(n & BigInt(0xFF));
        n >>= 8n;
    }
    return buf;
}