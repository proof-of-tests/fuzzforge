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
