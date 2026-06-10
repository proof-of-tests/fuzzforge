use std::{
    fs,
    io::{self, Read, Write},
    path::PathBuf,
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use fuzzforge::{
    DEFAULT_FUEL, DEFAULT_MEMORY_BYTES, HLL_BUCKETS, HLL_PRECISION, RunConfig, Store,
    hash_wasm_file, run_wasm,
};

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

        /// Read guest stdin bytes from this file instead of process stdin.
        #[arg(long)]
        stdin_file: Option<PathBuf>,

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
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Run {
            wasm,
            stdin_file,
            store,
            fuel,
            memory_bytes,
            invoke,
            no_stdout,
        } => {
            let stdin = read_guest_stdin(stdin_file.as_ref())?;
            let config = RunConfig {
                fuel,
                memory_bytes,
                invoke,
            };
            let result = run_wasm(&wasm, stdin, &store, config)
                .with_context(|| format!("failed to run {}", wasm.display()))?;
            if !no_stdout {
                io::stdout()
                    .write_all(&result.stdout)
                    .context("failed to write guest stdout")?;
            }
            eprintln!("program_hash={}", result.program_hash);
            eprintln!("status={}", result.status);
            eprintln!("fuel_consumed={}", result.fuel_consumed);
            eprintln!("hll_precision={HLL_PRECISION}");
            eprintln!("hll_buckets={HLL_BUCKETS}");
            eprintln!("hll_runs={}", result.run_count);
            eprintln!("hll_estimate={:.3}", result.estimated_observations);
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
    }
    Ok(())
}

fn read_guest_stdin(stdin_file: Option<&PathBuf>) -> Result<Vec<u8>> {
    match stdin_file {
        Some(path) => {
            fs::read(path).with_context(|| format!("failed to read stdin file {}", path.display()))
        }
        None => {
            let mut bytes = Vec::new();
            io::stdin()
                .read_to_end(&mut bytes)
                .context("failed to read process stdin")?;
            Ok(bytes)
        }
    }
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
