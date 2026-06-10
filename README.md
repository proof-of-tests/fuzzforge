# FuzzForge

FuzzForge runs deterministic local WebAssembly fuzz tests with `wasmi` and stores
compact HyperLogLog observations per WASM program hash.

## Usage

```sh
cargo run -- run ./test.wasm --stdin-file ./input.bin
cargo run -- stats ./test.wasm
cargo run -- list
```

The `run` command forwards captured guest stdout to process stdout by default and
prints run metadata to stderr. Use `--no-stdout` to suppress stdout forwarding.

## Example WASI Program

`examples/echo-wasi/` contains a tiny Rust program that reads stdin and copies it
to stdout. Build and run it from the repository root:

```sh
rustup target add wasm32-wasip1
cargo build \
  --manifest-path examples/echo-wasi/Cargo.toml \
  --target wasm32-wasip1 \
  --release \
  --target-dir target/echo-wasi
printf 'hello fuzzforge' | cargo run -- run \
  target/echo-wasi/wasm32-wasip1/release/echo-wasi.wasm \
  --store .fuzzforge/examples
```

## Determinism

The runner supports a strict WASI preview1 subset:

- stdin reads from fd `0`
- stdout writes to fd `1`
- empty args/env queries
- stdio fd metadata
- deterministic `proc_exit`

Modules importing clocks, randomness, filesystem, network, stderr-only behavior,
or unsupported WASI APIs are rejected before execution.

## HLL Storage

HLL records live under `.fuzzforge/hll/<program-hash>.json` by default.
Program hashes are lowercase BLAKE3 hashes of the raw WASM bytes.

Each run inserts one execution observation into a fixed-size HLL sketch:

- program hash
- stdin hash
- stdout hash
- exit/trap status
- fuel consumed

The HLL precision is fixed at `p = 6`, which means `2^6 = 64` buckets. This is
intentionally compact and coarse, with an expected relative error of roughly 13%.
The sketch implementation is maintained in this crate instead of depending on
an external HyperLogLog package.
