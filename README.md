[![Crates.io](https://img.shields.io/crates/v/nmt-rs.svg)](https://crates.io/crates/nmt-rs)
[![docs.rs](https://img.shields.io/docsrs/nmt-rs)](https://docs.rs/nmt-rs)
[![License](https://img.shields.io/crates/l/nmt-rs.svg)](https://github.com/Sovereign-Labs/nmt-rs#license)
[![CI](https://github.com/Sovereign-Labs/nmt-rs/actions/workflows/rust.yml/badge.svg?branch=master)](https://github.com/Sovereign-Labs/nmt-rs/actions/workflows/rust.yml)
[![codecov](https://codecov.io/gh/Sovereign-Labs/nmt-rs/branch/master/graph/badge.svg?token=Q8U6SLAZOT)](https://codecov.io/gh/Sovereign-Labs/nmt-rs)

# NMT

An implementation of a namespaced merkle tree in Rust.

## Warning

This code has not been audited, and may contain critical vulnerabilities. Do not attempt to use in production.

## Functionality

- [x] Compute merkle root  

- [x] Create index-based range proofs  

- [x] Verify index-based range proofs

- [x] Create namespace range proofs

- [x] Verify namespace range proofs

- [x] Narrow namespace range proofs: supply part of the range to generate a proof for the remaining sub-range

## Benchmarks

Benchmarks use [Criterion](https://github.com/bheisler/criterion.rs) and cover tree construction,
namespace proof generation, and proof verification/narrowing:

```sh
cargo bench                       # run everything
cargo bench -- nmt/verify         # run benchmarks matching a filter
cargo bench --bench go_parity     # counterparts of the celestiaorg/nmt Go benchmarks
```

## License

Licensed under the [Apache License, Version 2.0](./LICENSE).

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this repository by you, as defined in the Apache-2.0 license, shall be
licensed as above, without any additional terms or conditions.
