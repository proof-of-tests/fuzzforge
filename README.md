# FuzzForge

FuzzForge runs deterministic local WebAssembly fuzz tests with `wasmi` and stores
compact HyperLogLog bucket witnesses per WASM program hash.

## Usage

```sh
cargo run -- run ./test.wasm
cargo run -- run ./test.wasm --count=100
cargo run -- run ./test.wasm --count=1000 --save-fuel-interval=1000000000
cargo run -- run ./test.wasm --seed 68656c6c6f
cargo run -- stats ./test.wasm
cargo run -- verify ./test.wasm
cargo run -- list
cargo run -- auth login
cargo run -- upload ./test.wasm
cargo run -- run ./test.wasm --count=100 --submit-url
cargo run -- submit ./test.wasm
cargo run -- corpus
cargo run -- rate
```

The `run` command sends a seed to the guest as stdin. If `--seed <hex>` is not
provided, fuzzforge generates random seeds. Use `--count <n>` to execute
multiple runs with different generated seeds. `--seed` is accepted only when
`--count=1`. Captured guest stdout is hashed into the observation hash, but is
not persisted or forwarded to process stdout. The command prints the previous
HLL estimate as `proven_before=<estimate>`, then updates
`proven_added=<estimate>` after each HLL sketch update. When stderr is a
terminal, the progress line includes a spinner while a run is executing.
For multi-run batches, fuzzforge keeps the compiled WASM module and HLL record
in memory, then persists progress after `--save-fuel-interval` guest fuel has
been consumed and once more at the end of the batch.

Use `fuzzforge upload <wasm>` to upload a WASM module to the API. Use
`--submit-url <url>` on `run` to submit the updated HLL proof after the batch
finishes. Use `--submit-url` without a value to submit to the public FuzzForge
API at `https://fuzzforge.lemmih.com`. You can also submit an existing local
proof with `fuzzforge submit <wasm>`. Proof submission does not upload the WASM
module, so upload it once before submitting proofs for a new program. If
`--api-url` is omitted for network commands, fuzzforge reads `FUZZFORGE_API_URL`
and otherwise defaults to `https://fuzzforge.lemmih.com`. Submitted proofs must
use the current verifier version settings. Version 1 uses the default `fuel`,
`memory_bytes`, and `_start` invocation.

Use `fuzzforge corpus` to continuously fetch repository-associated WASM modules
from the API, download each module, fetch the central proof as the initial HLL
state, spend `10_000_000_000` guest fuel on each program using generated seeds,
upload each new proof entry as soon as it is found, and then start the corpus
again. The command only runs modules whose metadata reports a
`github_repository`. Downloaded modules are cached under the user cache
directory. Use `--fuel-budget <fuel>` to override the per-program fuel budget.

WASM modules can optionally report FuzzForge metadata by handling a `--metadata`
argument. When run with that argument, the module should print a JSON object to
stdout and exit successfully instead of running a fuzz test:

```json
{
  "github_repository": "owner/repo",
  "component_name": "",
  "version": "1.2.3"
}
```

`github_repository` can be omitted, null, or empty for unassociated modules.
`component_name` is optional and may be an empty string. `version` is required
for `--metadata` responses and must be SemVer.

Unassociated WASM uploads do not require authentication. Associated WASM uploads
require a GitHub App user token for a user with write or admin access to the
reported repository. Run `fuzzforge auth login` before uploading associated
WASM. Modules that do not print metadata or a repository are treated as
unassociated. The CLI uses the GitHub App device flow and stores token data
under `$XDG_CONFIG_HOME/fuzzforge/github.json`, or
`$HOME/.config/fuzzforge/github.json` when `XDG_CONFIG_HOME` is not set.

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

Each run creates one execution observation hash. The HLL record keeps only the
best witness for each fixed bucket:

- seed bytes as hex
- verifier version
- observation hash

`fuzzforge verify` reloads the stored bucket witnesses, reruns the program from
each witness seed using the recorded verifier version, and rebuilds the HLL
buckets to ensure the persisted witnesses are verifiable.
Observation hashes include the program hash, seed, stdout hash, exit/trap
status, and verifier-version execution settings. They intentionally exclude
fuel consumed, because compact bucket records do not preserve original run order.

The HLL precision is fixed at `p = 6`, which means `2^6 = 64` buckets. This is
intentionally compact and coarse, with an expected relative error of roughly 13%.
Records therefore store at most 64 witnesses per program.
The sketch implementation is maintained in this crate instead of depending on
an external HyperLogLog package.

## Cloudflare Backend

The Worker API lives in `worker/src/index.ts` and uses:

- R2 for `PUT/GET /api/programs/:program_hash/wasm`
- D1 for `GET /api/programs?associated=true` associated program discovery
- D1 for `GET /api/programs/:program_hash` metadata
- D1 for `POST/GET /api/programs/:program_hash/proof`
- GitHub App user tokens for associated WASM upload authorization
- bounded D1 HLL bucket witnesses for `GET /api/hash-results`
- Server-sent events for `GET /api/hash-results/stream`

Uploads are treated as untrusted input. The Worker verifies that uploaded WASM
bytes match the requested program hash before storing them. The Worker then runs
the module with empty stdin and argv `fuzzforge --metadata`. If metadata reports
a repository, the Worker requires an `Authorization: Bearer <token>` header,
checks `GET /user`, then checks `GET /repos/:owner/:repo`, accepting only tokens
whose effective repository permissions include `push` or `admin`. Empty output
or a non-success exit means the module is unassociated and the upload remains
unauthenticated.

After metadata validation, the Worker runs one verifier-version test iteration
with a fixed 32-byte zero seed and stores the consumed fuel as
`average_fuel_consumed` with `fuel_samples = 1`. Re-uploading the same program
does not reset existing fuel samples, so later random-seed sampling can refine
the average.

Proof uploads are verified inside the Worker with a Rust/wasmi verifier compiled
to WASM: each submitted bucket witness is rerun against the stored WASM, and
only newly verified witnesses are merged into the server-owned HLL buckets.

D1 stores one program metadata row per uploaded WASM and at most `2^6 = 64` HLL
bucket witness rows per program. WASM bytes live in R2 at the deterministic
content-hash key. Each witness stores only the verifier version, seed, and
observation hash; runtime settings are determined by the verifier version, not
by submitters. Concurrent proof submissions update bucket rows with SQL upserts
that keep the smallest verified observation hash for that bucket, which is
equivalent to the highest HLL rank. The rank is derived when a proof is read; it
is not stored. The live counter is derived by summing current HLL estimates.

Create the Cloudflare resources once:

```sh
npx wrangler d1 create fuzzforge
npx wrangler r2 bucket create fuzzforge-wasm
```

Put the returned D1 database id into the GitHub repository variable
`CLOUDFLARE_D1_DATABASE_ID`. Deployment also requires the
`CLOUDFLARE_API_TOKEN` secret and the `CLOUDFLARE_ACCOUNT_ID` repository
variable. Associated WASM uploads require a GitHub App with device flow enabled
and repository metadata read permission. Set `GITHUB_APP_CLIENT_ID` as a Worker
variable or secret so the CLI can start the device flow. Optional repository
variables override defaults:

- `CLOUDFLARE_D1_DATABASE_NAME` defaults to `fuzzforge`
- `CLOUDFLARE_R2_BUCKET_NAME` defaults to `fuzzforge-wasm`
- `CLOUDFLARE_WORKER_NAME` defaults to `fuzzforge-api`
- `CLOUDFLARE_WORKER_DOMAIN` defaults to `fuzzforge.lemmih.com`
- `CLOUDFLARE_WORKER_ZONE_NAME` defaults to `lemmih.com`

CI runs Rust integration tests and Worker end-to-end tests on pull requests and
pushes to `main`. Pushes to `main` also apply D1 migrations and deploy the
Worker to the custom domain. The Worker owns the full hostname so the API and
future website can be served from the same origin.
