mod api;
mod cli;
mod corpus;
mod progress;
mod rate;

use std::{
    io::{self, IsTerminal},
    path::PathBuf,
    time::Duration,
};

use anyhow::{Context, Result};
use clap::Parser;
use fuzzforge::{
    RunConfig, RunSession, Store, generate_seed, hash_wasm_file, seed_from_hex, verify_wasm,
};

use crate::{
    api::{api_url_or_env, github_auth_login, submit_bug_seed, submit_proof, upload_wasm},
    cli::{AuthCommand, Cli, Command},
    corpus::run_corpus,
    progress::ProgressDisplay,
    rate::watch_rate,
};

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Auth { command } => match command {
            AuthCommand::Login {
                api_url,
                timeout_seconds,
            } => {
                if timeout_seconds == 0 {
                    anyhow::bail!("--timeout-seconds must be greater than zero");
                }
                let api_url = api_url_or_env(api_url)?;
                github_auth_login(&api_url, Duration::from_secs(timeout_seconds))?;
            }
        },
        Command::Run {
            wasm,
            seed,
            seed_bytes,
            count,
            store,
            fuel,
            save_fuel_interval,
            memory_bytes,
            invoke,
            submit_url,
            submit_timeout_seconds,
        } => {
            if count == 0 {
                anyhow::bail!("--count must be greater than zero");
            }
            if seed.is_some() && count != 1 {
                anyhow::bail!("--seed can only be used when --count=1");
            }
            if save_fuel_interval == 0 {
                anyhow::bail!("--save-fuel-interval must be greater than zero");
            }
            if submit_url.is_some() && submit_timeout_seconds == 0 {
                anyhow::bail!("--submit-timeout-seconds must be greater than zero");
            }

            let config = RunConfig {
                fuel,
                memory_bytes,
                invoke,
            };
            if submit_url.is_some() && config != RunConfig::default() {
                anyhow::bail!(
                    "proof submission requires verifier version 1 settings; remove custom --fuel, --memory-bytes, and --invoke options"
                );
            }

            let explicit_seed = match seed.as_deref() {
                Some(seed) => Some(
                    seed_from_hex(seed)
                        .with_context(|| format!("failed to parse seed `{seed}`"))?,
                ),
                None => None,
            };
            let mut session = RunSession::from_wasm_path(&wasm, &store, config)
                .with_context(|| format!("failed to prepare {}", wasm.display()))?;
            let proven_before = session.stats().estimated_observations;
            let mut progress = ProgressDisplay::start(proven_before, io::stderr().is_terminal());
            let submit_url_ref = submit_url.as_deref();
            let submit_timeout = Duration::from_secs(submit_timeout_seconds);

            for _ in 0..count {
                let seed = match explicit_seed.as_ref() {
                    Some(seed) => seed.clone(),
                    None => generate_seed(seed_bytes)?,
                };
                let result = session
                    .run(seed)
                    .with_context(|| format!("failed to run {}", wasm.display()))?;
                session
                    .save_after_fuel(save_fuel_interval)
                    .with_context(|| {
                        format!("failed to save HLL record for {}", session.program_hash())
                    })?;
                if result.bug_found {
                    eprintln!(
                        "bug_seed={} stderr_bytes={}",
                        result.seed_hex,
                        result.stderr.len()
                    );
                    if let Some(api_url) = submit_url_ref {
                        submit_bug_seed(
                            api_url,
                            &result.program_hash,
                            &result.seed_hex,
                            submit_timeout,
                        )?;
                    }
                }
                progress.update(result.estimated_observations)?;
            }

            session.save_pending().with_context(|| {
                format!("failed to save HLL record for {}", session.program_hash())
            })?;
            progress.finish()?;

            if let Some(api_url) = submit_url.as_deref() {
                if session.record().bucket_witnesses().next().is_some() {
                    submit_proof(api_url, session.record(), submit_timeout)?;
                }
            }
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
                    "{} estimate={:.3} precision={} buckets={}",
                    stats.program_hash,
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
        Command::Upload {
            wasm,
            api_url,
            timeout_seconds,
        } => {
            let api_url = api_url_or_env(api_url)?;
            if timeout_seconds == 0 {
                anyhow::bail!("--timeout-seconds must be greater than zero");
            }
            upload_wasm(&api_url, &wasm, Duration::from_secs(timeout_seconds))?;
        }
        Command::Submit {
            wasm,
            store,
            api_url,
            timeout_seconds,
        } => {
            let api_url = api_url_or_env(api_url)?;
            if timeout_seconds == 0 {
                anyhow::bail!("--timeout-seconds must be greater than zero");
            }
            let program_hash = hash_wasm_file(&wasm)
                .with_context(|| format!("failed to hash {}", wasm.display()))?;
            let record = Store::new(store)
                .load_or_new(&program_hash)
                .with_context(|| format!("failed to load HLL record for {program_hash}"))?;
            submit_proof(&api_url, &record, Duration::from_secs(timeout_seconds))?;
        }
        Command::Corpus {
            api_url,
            fuel_budget,
            timeout_seconds,
        } => {
            if fuel_budget == 0 {
                anyhow::bail!("--fuel-budget must be greater than zero");
            }
            if timeout_seconds == 0 {
                anyhow::bail!("--timeout-seconds must be greater than zero");
            }
            let api_url = api_url_or_env(api_url)?;
            run_corpus(&api_url, fuel_budget, Duration::from_secs(timeout_seconds))?;
        }
        Command::Rate {
            api_url,
            window_seconds,
        } => {
            if window_seconds == 0 {
                anyhow::bail!("--window-seconds must be greater than zero");
            }
            let api_url = api_url_or_env(api_url)?;
            watch_rate(&api_url, Duration::from_secs(window_seconds))?;
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
