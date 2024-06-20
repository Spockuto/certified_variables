Certified variables
===================

This is a PoC canister `cert_var_backend` for using Certified Variables with an example of a canister which stores User. `cert_verify` and `cert_verify_js` demonstrates how you can verify the certification in Rust and JavaScript respectively.

> **_NOTE:_** `canister_id` and `url` are hardcoded and needs to be changes accordingly during deployment.

```
dfx start --background
dfx deploy

# Rust verification
cargo run --release -p cert_verify

# JS verification
cd src/cert_verify_js
node index.js

```