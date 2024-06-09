Certified variables [WIP]
=========================

This is a PoC canister `cert_var_backend` for using Certified Variables with an example of an counter canister. `cert_verify` demonstrates how you can verify the certification in Rust

```
dfx start --background

dfx ping # get root key

cat .dfx/canister_ids.json # get canister_id of cert_var_backend

# Call inc to increase the counter
dfx canister call cert_var_backend inc '()'

cargo run "$( dfx canister call cert_var_backend get '()')"
```
