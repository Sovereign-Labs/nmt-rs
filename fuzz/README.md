# Fuzzing

Install [cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz.html) and a nightly Rust toolchain, then run a target from the repository root:

```sh
cargo install cargo-fuzz --locked
rustup toolchain install nightly
cargo +nightly fuzz run <target> -- -max_total_time=60
```

`cargo +nightly fuzz list` shows the targets:

| Target | What it checks |
| --- | --- |
| `malformed_proofs` | Arbitrary presence and absence proofs, with arbitrary ranges, sibling bounds and hashes, given to every namespace verifier and to narrowing. Any of them may return an error, but none may panic. |
| `namespace_proofs` | Honestly built trees. Namespace queries must return the right leaves with a proof that verifies; ranges anywhere in the tree, including across namespaces, must verify as merkle proofs, and as namespace proofs exactly when they lie within one namespace (and as complete only when they cover it). Also checks single-leaf proofs, tampered leaf data, out-of-order leaves and a hasher that disagrees with the proof about the max namespace. |
| `narrow_proofs` | Narrowing an honest proof, over a range which may span namespaces, must give exactly the proof the tree builds for the narrower range. Narrowing with a wrong extra leaf must fail or give a proof which doesn't verify. Narrowing arbitrary proofs must not panic. |
| `forged_proofs` | Mutates honest proofs, mostly with genuine nodes of the same tree: ranges, sibling order and contents, sibling namespace bounds, the absence-proof leaf, the proof variant, the `ignore_max_ns` flag, the claimed leaves and the queried namespace. Whatever still verifies must be true: a complete namespace proof must give exactly that namespace's leaves, and a range proof must give leaves which occur contiguously in that namespace. |
| `simple_merkle_proofs` | The plain merkle tree with `TmSha2Hasher`. Roots must match tendermint-rs, honest range, single-leaf and narrowed proofs must verify, and forged proofs must only verify for contiguous runs of leaves. Arbitrary proofs must not panic. |
| `deserialize_proofs` | Namespace proofs, plain merkle proofs and namespaced hashes in borsh, JSON, MessagePack (structs as arrays and as maps) and postcard. Honest values must round trip and still verify. Arbitrary bytes, and mutated encodings of honest values, must decode without panicking, round trip once decoded, and only then reach the verifiers. |

Range proofs don't authenticate their start index, here or in [celestiaorg/nmt](https://github.com/celestiaorg/nmt), because the tree size is inferred from the proof. A valid range proof therefore only shows that its leaves occur contiguously somewhere in the tree, which is what the targets check.

Namespaces are generated in several shapes, so that comparisons are decided at different byte positions: a repeated byte, a shared prefix with a short suffix, a single byte at an arbitrary position, values around the reserved and maximum namespaces, and fully arbitrary bytes. Trees draw their leaves' namespaces from a small palette, so namespaces usually hold several leaves. When the tree ignores the max namespace and holds other namespaces, the max namespace lies outside the root's range and can only be proven absent; the targets expect exactly that.

Shared generators and oracles live in `src/lib.rs`.

## Coverage

Each run grows the target's corpus in `fuzz/corpus/<target>/`. To see how much of `src/` the corpora cover, merged across every target or for the targets you name, run:

```sh
rustup component add --toolchain nightly llvm-tools-preview  # once
fuzz/coverage.sh [--fuzz SECONDS] [--html] [TARGET...]
```

`--fuzz SECONDS` first fuzzes each target for that long on every core, which creates the corpora on a fresh checkout and grows them afterwards; `fuzz/coverage.sh --fuzz 60` is a good start. A crash or slow input stops the script, leaving the reproducer in `fuzz/artifacts/<target>/`. `--html` also writes a per-line report to `fuzz/coverage/html/index.html`. Coverage only counts generic code which some target instantiates, so library code that no target calls doesn't appear in the totals at all. A warning that some functions have mismatched data is expected when merging targets, since each target compiles the shared code separately.

## Crashes

Crashes are saved under `fuzz/artifacts/<target>/`. Replay and minimize them with:

```sh
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<crash-file>
cargo +nightly fuzz tmin <target> fuzz/artifacts/<target>/<crash-file>
```

A crash or failed assertion needs investigation rather than suppression. Add a reproducer as a regression test before fixing it. Fuzzing has found an unordered-sibling panic and acceptance of fabricated data with an out-of-range absence proof, both since fixed, and narrowing time that grew with the claimed range rather than with the tree depth (regression test `test_range_proof_narrowing_is_logarithmic_in_claimed_range` in `src/lib.rs`).

## Development

Generated corpora, artifacts, coverage reports and build outputs are ignored by Git.

The fuzz package is separate from the library workspace. Format both packages after editing:

```sh
cargo fmt --all
cargo fmt --all --manifest-path fuzz/Cargo.toml
```
