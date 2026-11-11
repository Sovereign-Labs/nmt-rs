# Fuzzing

Install [cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz.html) and a nightly Rust toolchain, then run these commands from the repository root:

```sh
cargo install cargo-fuzz --locked
rustup toolchain install nightly
cargo +nightly fuzz run malformed_proofs -- -max_total_time=60
cargo +nightly fuzz run namespace_proofs -- -max_total_time=60
cargo +nightly fuzz run narrow_range -- -max_total_time=60
```

`malformed_proofs` constructs bounded proof objects with arbitrary ranges, sibling bounds, hashes, and presence/absence variants. Either public namespace verifier may return an error, but must not panic.

`namespace_proofs` builds sorted trees, checks namespace results against the input leaves, verifies complete and partial proofs, and requires rejection of altered leaf data or fabricated data for an absent namespace. It keeps the original root fixed. The input selects whether to tamper, allowing valid-only cases to remain in the corpus.

`narrow_range` builds a tree, proves a range and narrows the proof to a subrange. Untampered proofs must narrow to exactly the proof built for the subrange, and that proof must verify. Tampered siblings, ranges or extra leaves may make narrowing fail, but must not panic. Narrowing takes time linear in the claimed range length, so tampered ranges are bounded to 2^16.

All targets exercise 29-byte namespace IDs and both `ignore_max_ns` settings. Namespace bytes are repeated from a single byte to make boundary comparisons and duplicate namespaces easy to generate. The semantic target includes maximum-namespace leaves but skips complete-namespace queries for that reserved namespace when `ignore_max_ns` is enabled. Inputs are bounded to 32 tree leaves, 16 malformed-proof leaves, 64 bytes per input leaf, and 32 siblings.

Crashes are saved under `fuzz/artifacts/<target>/`. Replay and minimize them with:

```sh
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<crash-file>
cargo +nightly fuzz tmin <target> fuzz/artifacts/<target>/<crash-file>
```

The targets intentionally expose verifier defects; a crash or failed semantic assertion needs investigation rather than suppression. Initial smoke runs found an unordered-sibling panic and acceptance of fabricated data with an out-of-range absence proof. Reproducers are in `tests/fuzz_regressions.rs`, ignored until the verifier bugs are fixed; the fuzz targets still fail on these cases. Run the reproducers explicitly with:

```sh
cargo test --test fuzz_regressions -- --ignored
```

Generated corpora, artifacts, and build outputs are ignored by Git.

The fuzz package is separate from the library workspace. Format both packages after editing:

```sh
cargo fmt --all
cargo fmt --all --manifest-path fuzz/Cargo.toml
```
