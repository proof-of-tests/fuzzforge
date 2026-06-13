use std::path::PathBuf;

use clap::{Parser, Subcommand};
use fuzzforge::{
    DEFAULT_FUEL, DEFAULT_MEMORY_BYTES, DEFAULT_SAVE_FUEL_INTERVAL, DEFAULT_SEED_BYTES,
};

use crate::{
    api::{DEFAULT_API_URL, DEFAULT_SUBMIT_TIMEOUT_SECONDS},
    corpus::DEFAULT_CORPUS_FUEL_BUDGET,
    rate::DEFAULT_RATE_WINDOW_SECONDS,
};

const DEFAULT_RUN_COUNT: usize = 1;

#[derive(Debug, Parser)]
#[command(version, about = "Run deterministic local WASM fuzz tests with wasmi")]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Authenticate with the GitHub App for associated WASM uploads.
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },

    /// Run a WASM fuzz test locally and update its HLL sketch.
    Run {
        /// Path to the WASM module.
        wasm: PathBuf,

        /// Guest stdin seed as hex. If omitted, fuzzforge generates a random seed.
        #[arg(long)]
        seed: Option<String>,

        /// Number of random seed bytes to generate when --seed is omitted.
        #[arg(long, default_value_t = DEFAULT_SEED_BYTES)]
        seed_bytes: usize,

        /// Number of fuzz runs to execute, each with a different generated seed.
        #[arg(long, default_value_t = DEFAULT_RUN_COUNT)]
        count: usize,

        /// Store directory for HLL data.
        #[arg(long, default_value = ".fuzzforge")]
        store: PathBuf,

        /// Fuel to assign to the wasmi store.
        #[arg(long, default_value_t = DEFAULT_FUEL)]
        fuel: u64,

        /// Persist HLL progress after this much guest fuel is consumed.
        #[arg(long, default_value_t = DEFAULT_SAVE_FUEL_INTERVAL)]
        save_fuel_interval: u64,

        /// Maximum bytes for each guest linear memory.
        #[arg(long, default_value_t = DEFAULT_MEMORY_BYTES)]
        memory_bytes: usize,

        /// Invoke a no-arg export instead of the default WASI _start export.
        #[arg(long)]
        invoke: Option<String>,

        /// Submit the updated proof to a fuzzforge API base URL.
        #[arg(long, num_args = 0..=1, default_missing_value = DEFAULT_API_URL)]
        submit_url: Option<String>,

        /// HTTP timeout for proof submission.
        #[arg(long, default_value_t = DEFAULT_SUBMIT_TIMEOUT_SECONDS)]
        submit_timeout_seconds: u64,
    },

    /// Show HLL statistics for a WASM file or a program hash.
    Stats {
        /// WASM path or 64-character lowercase BLAKE3 program hash.
        wasm_or_hash: String,

        /// Store directory for HLL data.
        #[arg(long, default_value = ".fuzzforge")]
        store: PathBuf,
    },

    /// List all HLL records in a store.
    List {
        /// Store directory for HLL data.
        #[arg(long, default_value = ".fuzzforge")]
        store: PathBuf,
    },

    /// Re-run every stored seed and verify expected outputs and HLL hashes.
    Verify {
        /// Path to the WASM module.
        wasm: PathBuf,

        /// Store directory for HLL data.
        #[arg(long, default_value = ".fuzzforge")]
        store: PathBuf,
    },

    /// Upload a WASM file to a fuzzforge API.
    Upload {
        /// Path to the WASM module.
        wasm: PathBuf,

        /// FuzzForge API base URL. Defaults to FUZZFORGE_API_URL or the public FuzzForge API.
        #[arg(long)]
        api_url: Option<String>,

        /// HTTP timeout for WASM upload.
        #[arg(long, default_value_t = DEFAULT_SUBMIT_TIMEOUT_SECONDS)]
        timeout_seconds: u64,
    },

    /// Submit a stored HLL proof to a fuzzforge API.
    Submit {
        /// Path to the WASM module.
        wasm: PathBuf,

        /// Store directory for HLL data.
        #[arg(long, default_value = ".fuzzforge")]
        store: PathBuf,

        /// FuzzForge API base URL. Defaults to FUZZFORGE_API_URL or the public FuzzForge API.
        #[arg(long)]
        api_url: Option<String>,

        /// HTTP timeout for proof submission.
        #[arg(long, default_value_t = DEFAULT_SUBMIT_TIMEOUT_SECONDS)]
        timeout_seconds: u64,
    },

    /// Continuously run every repository-associated WASM program from a fuzzforge API.
    Corpus {
        /// FuzzForge API base URL. Defaults to FUZZFORGE_API_URL or the public FuzzForge API.
        #[arg(long)]
        api_url: Option<String>,

        /// Guest fuel to spend on each program before moving to the next one.
        #[arg(long, default_value_t = DEFAULT_CORPUS_FUEL_BUDGET)]
        fuel_budget: u64,

        /// HTTP timeout for program downloads and proof submissions.
        #[arg(long, default_value_t = DEFAULT_SUBMIT_TIMEOUT_SECONDS)]
        timeout_seconds: u64,
    },

    /// Watch the live test execution rate from a fuzzforge API.
    Rate {
        /// FuzzForge API base URL. Defaults to FUZZFORGE_API_URL or the public FuzzForge API.
        #[arg(long)]
        api_url: Option<String>,

        /// Smoothing window, in seconds, for the printed rate.
        #[arg(long, default_value_t = DEFAULT_RATE_WINDOW_SECONDS)]
        window_seconds: u64,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum AuthCommand {
    /// Login with the GitHub App device flow.
    Login {
        /// FuzzForge API base URL. Defaults to FUZZFORGE_API_URL or the public FuzzForge API.
        #[arg(long)]
        api_url: Option<String>,

        /// HTTP timeout for auth requests.
        #[arg(long, default_value_t = DEFAULT_SUBMIT_TIMEOUT_SECONDS)]
        timeout_seconds: u64,
    },
}
