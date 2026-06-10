# FuzzForge

FuzzForge runs deterministic local WebAssembly fuzz tests with `wasmi` and stores
compact HyperLogLog observations per WASM program hash.

## Usage

```sh
cargo run -- run ./test.wasm
cargo run -- run ./test.wasm --count=100
cargo run -- run ./test.wasm --seed 68656c6c6f
cargo run -- stats ./test.wasm
cargo run -- verify ./test.wasm
cargo run -- list
```

The `run` command sends a seed to the guest as stdin. If `--seed <hex>` is not
provided, fuzzforge generates random seeds and stores them with each observation.
Use `--count <n>` to execute multiple runs with different generated seeds.
`--seed` is accepted only when `--count=1`. Captured guest stdout is stored and
hashed, but never forwarded to process stdout. The command prints the previous
HLL estimate as `proven_before=<estimate>`, then updates
`proven_added=<estimate>` after each HLL sketch update.

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
cargo run -- run \
  target/echo-wasi/wasm32-wasip1/release/echo-wasi.wasm \
  --seed 68656c6c6f2066757a7a666f726765 \
  --store .fuzzforge/examples
cargo run -- verify \
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

Each run stores its seed and expected result, then inserts one execution
observation into a fixed-size HLL sketch:

- program hash
- seed bytes as hex
- stdout hash
- exit/trap status
- fuel consumed

`fuzzforge verify` reloads the stored seeds, reruns the program, checks that the
new output/status/fuel match the stored expected values, and rebuilds the HLL
registers to ensure the persisted sketch matches the verifiable observations.

The HLL precision is fixed at `p = 6`, which means `2^6 = 64` buckets. This is
intentionally compact and coarse, with an expected relative error of roughly 13%.
The sketch implementation is maintained in this crate instead of depending on
an external HyperLogLog package.
