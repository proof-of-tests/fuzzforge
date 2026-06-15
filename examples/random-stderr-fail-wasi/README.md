# random-stderr-fail-wasi

This example is intended for long-term FuzzForge corpus testing. It reads the
seed from stdin, applies a deterministic stable hash, and writes to stderr when
`hash % 10_000_000 == 0`.

Build it from the repository root:

```sh
rustup target add wasm32-wasip1
cargo build \
  --manifest-path examples/random-stderr-fail-wasi/Cargo.toml \
  --target wasm32-wasip1 \
  --release \
  --target-dir target/random-stderr-fail-wasi
```

Uploading the compiled WASM to a FuzzForge API requires `fuzzforge auth login`
for a GitHub user with write or admin access to `proof-of-tests/fuzzforge`.
