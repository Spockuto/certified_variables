Certified variables [WIP]
=========================

This is a PoC canister `cert_var_backend` for using Certified Variables with an example of a canister which stores User. `cert_verify` demonstrates how you can verify the certification in Rust.

> **_NOTE:_** `canister_id` are hardcoded and needs to be changes accordingly during deployment.

```
dfx start --background
dfx deploy

cargo run --release -p cert_verify
```
