use std::{
    io::{self, Write},
    path::PathBuf,
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use fuzzforge::{
    DEFAULT_FUEL, DEFAULT_MEMORY_BYTES, DEFAULT_SEED_BYTES, RunConfig, Store, generate_seed,
    hash_wasm_file, run_wasm, seed_from_hex, verify_wasm,
};

const DEFAULT_RUN_COUNT: usize = 1;

#[derive(Debug, Parser)]
#[command(version, about = "Run deterministic local WASM fuzz tests with wasmi")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
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

        /// Maximum bytes for each guest linear memory.
        #[arg(long, default_value_t = DEFAULT_MEMORY_BYTES)]
        memory_bytes: usize,

        /// Invoke a no-arg export instead of the default WASI _start export.
        #[arg(long)]
        invoke: Option<String>,

        /// Do not forward captured guest stdout to process stdout.
        #[arg(long)]
        no_stdout: bool,
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
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Run {
            wasm,
            seed,
            seed_bytes,
            count,
            store,
            fuel,
            memory_bytes,
            invoke,
            no_stdout,
        } => {
            if count == 0 {
                anyhow::bail!("--count must be greater than zero");
            }
            if seed.is_some() && count != 1 {
                anyhow::bail!("--seed can only be used when --count=1");
            }
            let config = RunConfig {
                fuel,
                memory_bytes,
                invoke,
            };
            let program_hash = hash_wasm_file(&wasm)
                .with_context(|| format!("failed to hash {}", wasm.display()))?;
            let proven_before = Store::new(&store)
                .stats(&program_hash)
                .with_context(|| format!("failed to load HLL record for {program_hash}"))?
                .run_count;
            eprintln!("proven_before={proven_before}");
            let mut proven_total = proven_before;
            for _ in 0..count {
                let seed = match seed.as_ref() {
                    Some(seed) => seed_from_hex(seed)
                        .with_context(|| format!("failed to parse seed `{seed}`"))?,
                    None => generate_seed(seed_bytes)?,
                };
                let result = run_wasm(&wasm, seed, &store, config.clone())
                    .with_context(|| format!("failed to run {}", wasm.display()))?;
                if !no_stdout {
                    io::stdout()
                        .write_all(&result.stdout)
                        .context("failed to write guest stdout")?;
                }
                proven_total = result.run_count;
            }
            eprintln!(
                "proven_added={}",
                proven_total.saturating_sub(proven_before)
            );
        }
        Command::Stats {
            wasm_or_hash,
            store,
        } => {
            let program_hash = resolve_program_hash(&wasm_or_hash)
                .with_context(|| format!("failed to resolve `{wasm_or_hash}`"))?;
            let store = Store::new(store);
            let stats = store
                .stats(&program_hash)
                .with_context(|| format!("failed to load HLL record for {program_hash}"))?;
            println!("program_hash={}", stats.program_hash);
            println!("schema_version={}", stats.schema_version);
            println!("precision={}", stats.precision);
            println!("buckets={}", stats.buckets);
            println!("runs={}", stats.run_count);
            println!("stored_observations={}", stats.stored_observations);
            println!("estimated_observations={:.3}", stats.estimated_observations);
            println!(
                "last_observation_hash={}",
                stats.last_observation_hash.as_deref().unwrap_or("-")
            );
        }
        Command::List { store } => {
            let store = Store::new(store);
            for stats in store.list().context("failed to list HLL records")? {
                println!(
                    "{} runs={} estimate={:.3} precision={} buckets={}",
                    stats.program_hash,
                    stats.run_count,
                    stats.estimated_observations,
                    stats.precision,
                    stats.buckets
                );
            }
        }
        Command::Verify { wasm, store } => {
            let report = verify_wasm(&wasm, &store)
                .with_context(|| format!("failed to verify {}", wasm.display()))?;
            println!("program_hash={}", report.program_hash);
            println!("checked_observations={}", report.checked_observations);
            println!("sketch_matches={}", report.sketch_matches);
            if report.is_success() {
                println!("verification=ok");
            } else {
                for failure in &report.failures {
                    eprintln!("seed={} error={}", failure.seed_hex, failure.reason);
                }
                anyhow::bail!(
                    "verification failed for {} stored observations",
                    report.failures.len()
                );
            }
        }
    }
    Ok(())
}

fn resolve_program_hash(value: &str) -> Result<String> {
    let path = PathBuf::from(value);
    if path.exists() {
        return hash_wasm_file(&path);
    }
    if value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(value.to_ascii_lowercase());
    }
    anyhow::bail!("expected an existing WASM path or a 64-character BLAKE3 hash")
}
