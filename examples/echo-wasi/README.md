# echo-wasi

This example reads all bytes from stdin and copies them to stdout. Compile it to
WASI and run it through `fuzzforge` from the repository root:

```sh
rustup target add wasm32-wasip1
cargo build \
  --manifest-path examples/echo-wasi/Cargo.toml \
  --target wasm32-wasip1 \
  --release \
  --target-dir target/echo-wasi
cargo run -- run \
  target/echo-wasi/wasm32-wasip1/release/echo-wasi.wasm \
  --seed 68656c6c6f2066757a7a666f726765 \
  --store .fuzzforge/examples
cargo run -- verify \
  target/echo-wasi/wasm32-wasip1/release/echo-wasi.wasm \
  --store .fuzzforge/examples
```

The explicit seed above is the UTF-8 bytes for `hello fuzzforge`; the expected
guest stdout is the exact seed bytes.

When run with `--metadata`, the program prints FuzzForge metadata instead of
echoing stdin:

```json
{
  "github_repository": "proof-of-tests/fuzzforge",
  "component_name": "echo-wasi",
  "version": "0.1.0"
}
```

It also supports the legacy `--repository` query, which prints
`proof-of-tests/fuzzforge`. Uploading the compiled WASM to a FuzzForge API
therefore requires `fuzzforge auth login` for a GitHub user with write or admin
access to that repository.
