Certified variables
===================
This is proof of concept implementation to demo the usage of Certified Variables in the Internet Computer. The repository contains the following implmentations

* `cert_var_rust` implements the canister the Rust
* `cert_var_mo` implements the canister in Motoko
* `cert_verify_rust` implements the certificate verification in Rust
* `cert_verify_js` implements the certificate verification in JavaScript

> **_NOTE:_** `canister_id` and `url/host` are hardcoded and needs to be changes accordingly to test certificate verification.

## Steps

1. Start a local replica and deploy the canisters. This will deploy the Motoko and Rust canister.

```sh
dfx start --background
dfx deploy
```

2. To verify in Rust, replace the following variables in `src/cert_verify_rust/src/main.rs` with the local replica network and canister ID of either Motoko or Rust.
```rust
static URL: &str = "http://localhost:42783";
static CANISTER: &str = "ajuq4-ruaaa-aaaaa-qaaga-cai";
```
Verify using, 
```sh
cargo run --release -p cert_verify_rust
```

3. To verify in JavaScript, replace the following variables in `src/cert_verify_js/index.js` with the local replica network and canister ID of either Motoko or Rust.

```js
const canisterId = Principal.fromText("ajuq4-ruaaa-aaaaa-qaaga-cai");
const host = "http://localhost:42783";
```
Verify using, 
```sh
cd src/cert_verify_js
npm ci
node index.js

```

## Canister Interface
```c
type User = record {
    name: text;
    age: nat8;
};

type CertifiedUser = record {
    user : User;
    certificate : blob;
    witness : blob;
};

service : {
    "set_user": (User) -> (nat64);
    "get_user": (nat64) -> (CertifiedUser) query;
}
```