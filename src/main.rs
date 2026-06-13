use std::{
    fs,
    io::{self, IsTerminal, Write},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
    },
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use fuzzforge::{
    DEFAULT_FUEL, DEFAULT_MEMORY_BYTES, DEFAULT_SAVE_FUEL_INTERVAL, DEFAULT_SEED_BYTES, HllRecord,
    RunConfig, RunSession, Store, generate_seed, hash_wasm_file, query_wasm_metadata,
    seed_from_hex, verify_wasm,
};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};

const DEFAULT_RUN_COUNT: usize = 1;
const DEFAULT_SUBMIT_TIMEOUT_SECONDS: u64 = 30;
const DEFAULT_RATE_WINDOW_SECONDS: u64 = 10;
const DEFAULT_CORPUS_FUEL_BUDGET: u64 = 10_000_000_000;
const PROGRAM_LIST_PAGE_SIZE: usize = 100;
const API_URL_ENV: &str = "FUZZFORGE_API_URL";
const DEFAULT_API_URL: &str = "https://fuzzforge.lemmih.com";

#[derive(Debug, Parser)]
#[command(version, about = "Run deterministic local WASM fuzz tests with wasmi")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
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

        /// Submit the WASM file and updated proof to a fuzzforge API base URL.
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

    /// Submit a stored HLL proof and its WASM file to a fuzzforge API.
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

        /// Store directory for downloaded WASM modules and HLL data.
        #[arg(long, default_value = ".fuzzforge")]
        store: PathBuf,

        /// Guest fuel to spend on each program before moving to the next one.
        #[arg(long, default_value_t = DEFAULT_CORPUS_FUEL_BUDGET)]
        fuel_budget: u64,

        /// Number of random seed bytes to generate for each run.
        #[arg(long, default_value_t = DEFAULT_SEED_BYTES)]
        seed_bytes: usize,

        /// Persist HLL progress after this much guest fuel is consumed.
        #[arg(long, default_value_t = DEFAULT_SAVE_FUEL_INTERVAL)]
        save_fuel_interval: u64,

        /// HTTP timeout for program downloads and proof submissions.
        #[arg(long, default_value_t = DEFAULT_SUBMIT_TIMEOUT_SECONDS)]
        timeout_seconds: u64,

        /// Limit the number of full corpus cycles. Omit to run forever.
        #[arg(long)]
        cycles: Option<usize>,

        /// Seconds to sleep between corpus cycles.
        #[arg(long, default_value_t = 0)]
        cycle_sleep_seconds: u64,
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
enum AuthCommand {
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
                progress.update(result.estimated_observations)?;
            }
            session.save_pending().with_context(|| {
                format!("failed to save HLL record for {}", session.program_hash())
            })?;
            progress.finish()?;
            if let Some(api_url) = submit_url {
                submit_proof(
                    &api_url,
                    &wasm,
                    session.record(),
                    Duration::from_secs(submit_timeout_seconds),
                )?;
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
            submit_proof(
                &api_url,
                &wasm,
                &record,
                Duration::from_secs(timeout_seconds),
            )?;
        }
        Command::Corpus {
            api_url,
            store,
            fuel_budget,
            seed_bytes,
            save_fuel_interval,
            timeout_seconds,
            cycles,
            cycle_sleep_seconds,
        } => {
            if fuel_budget == 0 {
                anyhow::bail!("--fuel-budget must be greater than zero");
            }
            if save_fuel_interval == 0 {
                anyhow::bail!("--save-fuel-interval must be greater than zero");
            }
            if timeout_seconds == 0 {
                anyhow::bail!("--timeout-seconds must be greater than zero");
            }
            if cycles == Some(0) {
                anyhow::bail!("--cycles must be greater than zero");
            }
            let api_url = api_url_or_env(api_url)?;
            run_corpus(
                &api_url,
                &store,
                fuel_budget,
                seed_bytes,
                save_fuel_interval,
                Duration::from_secs(timeout_seconds),
                cycles,
                Duration::from_secs(cycle_sleep_seconds),
            )?;
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

fn run_corpus(
    api_url: &str,
    store: &PathBuf,
    fuel_budget: u64,
    seed_bytes: usize,
    save_fuel_interval: u64,
    timeout: Duration,
    cycles: Option<usize>,
    cycle_sleep: Duration,
) -> Result<()> {
    let client = Client::builder()
        .timeout(timeout)
        .build()
        .context("failed to build HTTP client")?;
    let mut completed_cycles = 0usize;
    loop {
        let programs = list_associated_programs(&client, api_url)?;
        eprintln!(
            "corpus_cycle={} associated_programs={}",
            completed_cycles + 1,
            programs.len()
        );
        let mut downloads = Vec::with_capacity(programs.len());
        for program in programs {
            match download_associated_program(&client, api_url, store, program) {
                Ok(Some(download)) => downloads.push(download),
                Ok(None) => {}
                Err(error) => eprintln!("download_error={error:#}"),
            }
        }

        for download in downloads {
            run_corpus_program(
                api_url,
                store,
                &download,
                fuel_budget,
                seed_bytes,
                save_fuel_interval,
                timeout,
            )
            .with_context(|| format!("failed to run {}", download.program.program_hash))?;
        }

        completed_cycles = completed_cycles.saturating_add(1);
        if cycles.is_some_and(|max_cycles| completed_cycles >= max_cycles) {
            return Ok(());
        }
        if !cycle_sleep.is_zero() {
            thread::sleep(cycle_sleep);
        }
    }
}

fn list_associated_programs(client: &Client, api_url: &str) -> Result<Vec<ProgramSummary>> {
    let base = api_url.trim_end_matches('/');
    let mut cursor: Option<String> = None;
    let mut programs = Vec::new();
    loop {
        let mut url = format!(
            "{base}/api/programs?associated=true&limit={}",
            PROGRAM_LIST_PAGE_SIZE
        );
        if let Some(cursor) = &cursor {
            url.push_str("&cursor=");
            url.push_str(cursor);
        }
        let response = client
            .get(&url)
            .send()
            .with_context(|| format!("failed to list programs from {url}"))?;
        ensure_success_ref(&response, "program listing")?;
        let page: ProgramListResponse = response.json().context("failed to parse program list")?;
        programs.extend(page.programs);
        match page.next_cursor {
            Some(next_cursor) => cursor = Some(next_cursor),
            None => return Ok(programs),
        }
    }
}

fn download_associated_program(
    client: &Client,
    api_url: &str,
    store: &PathBuf,
    program: ProgramSummary,
) -> Result<Option<CorpusDownload>> {
    let base = api_url.trim_end_matches('/');
    let wasm_url = format!("{base}/api/programs/{}/wasm", program.program_hash);
    let response = client
        .get(&wasm_url)
        .send()
        .with_context(|| format!("failed to download WASM from {wasm_url}"))?;
    ensure_success_ref(&response, "WASM download")?;
    let wasm = response.bytes().context("failed to read WASM download")?;
    let metadata =
        query_wasm_metadata(&wasm).context("failed to query downloaded WASM metadata")?;
    if metadata
        .and_then(|metadata| metadata.github_repository)
        .is_none()
    {
        eprintln!("skipped_unassociated={}", program.program_hash);
        return Ok(None);
    }

    let wasm_dir = store.join("wasm");
    fs::create_dir_all(&wasm_dir)
        .with_context(|| format!("failed to create {}", wasm_dir.display()))?;
    let wasm_path = wasm_dir.join(format!("{}.wasm", program.program_hash));
    let tmp = wasm_path.with_extension(format!("wasm.tmp.{}", std::process::id()));
    fs::write(&tmp, &wasm).with_context(|| format!("failed to write {}", tmp.display()))?;
    fs::rename(&tmp, &wasm_path).with_context(|| {
        format!(
            "failed to rename {} to {}",
            tmp.display(),
            wasm_path.display()
        )
    })?;

    let actual_hash = hash_wasm_file(&wasm_path)
        .with_context(|| format!("failed to hash {}", wasm_path.display()))?;
    if actual_hash != program.program_hash {
        anyhow::bail!(
            "downloaded WASM hash mismatch: expected {}, got {}",
            program.program_hash,
            actual_hash
        );
    }

    Ok(Some(CorpusDownload { program, wasm_path }))
}

fn run_corpus_program(
    api_url: &str,
    store: &PathBuf,
    download: &CorpusDownload,
    fuel_budget: u64,
    seed_bytes: usize,
    save_fuel_interval: u64,
    timeout: Duration,
) -> Result<()> {
    let mut session = RunSession::from_wasm_path(&download.wasm_path, store, RunConfig::default())
        .with_context(|| format!("failed to prepare {}", download.wasm_path.display()))?;
    let mut fuel_spent = 0u64;
    eprintln!(
        "program_start={} repository={} fuel_budget={}",
        download.program.program_hash,
        download.program.github_repository.as_deref().unwrap_or("-"),
        fuel_budget
    );
    while fuel_spent < fuel_budget {
        let result = session
            .run(generate_seed(seed_bytes)?)
            .with_context(|| format!("failed to run {}", download.wasm_path.display()))?;
        fuel_spent = fuel_spent.saturating_add(result.fuel_consumed);
        session
            .save_after_fuel(save_fuel_interval)
            .with_context(|| format!("failed to save HLL record for {}", session.program_hash()))?;
        if result.fuel_consumed == 0 {
            eprintln!("program_zero_fuel={}", session.program_hash());
            break;
        }
    }
    session
        .save_pending()
        .with_context(|| format!("failed to save HLL record for {}", session.program_hash()))?;
    submit_proof(api_url, &download.wasm_path, session.record(), timeout)?;
    eprintln!(
        "program_done={} fuel_spent={} estimated_observations={:.3}",
        session.program_hash(),
        fuel_spent,
        session.stats().estimated_observations
    );
    Ok(())
}

fn api_url_or_env(api_url: Option<String>) -> Result<String> {
    match api_url {
        Some(api_url) => Ok(api_url),
        None => Ok(std::env::var(API_URL_ENV).unwrap_or_else(|_| DEFAULT_API_URL.to_string())),
    }
}

fn github_auth_login(api_url: &str, timeout: Duration) -> Result<()> {
    let client = Client::builder()
        .timeout(timeout)
        .build()
        .context("failed to build HTTP client")?;
    let base = api_url.trim_end_matches('/');
    let config_url = format!("{base}/api/auth/github");
    let config: GitHubAuthConfig = client
        .get(&config_url)
        .send()
        .with_context(|| format!("failed to load GitHub auth config from {config_url}"))?
        .error_for_status()
        .context("GitHub auth config request failed")?
        .json()
        .context("failed to parse GitHub auth config")?;
    let client_id = config
        .client_id
        .filter(|value| !value.is_empty())
        .context("FuzzForge API has not configured GITHUB_APP_CLIENT_ID")?;

    let device: DeviceCodeResponse = client
        .post("https://github.com/login/device/code")
        .header(reqwest::header::ACCEPT, "application/json")
        .query(&[("client_id", client_id.as_str())])
        .send()
        .context("failed to start GitHub device flow")?
        .error_for_status()
        .context("GitHub device flow request failed")?
        .json()
        .context("failed to parse GitHub device flow response")?;

    eprintln!(
        "Open {} and enter code {}",
        device.verification_uri, device.user_code
    );

    let started_at = unix_now()?;
    let mut interval = device.interval.unwrap_or(5).max(1);
    loop {
        thread::sleep(Duration::from_secs(interval));
        if unix_now()?.saturating_sub(started_at) >= device.expires_in {
            anyhow::bail!("GitHub device code expired; run `fuzzforge auth login` again");
        }
        let response: GitHubTokenResponse = client
            .post("https://github.com/login/oauth/access_token")
            .header(reqwest::header::ACCEPT, "application/json")
            .query(&[
                ("client_id", client_id.as_str()),
                ("device_code", device.device_code.as_str()),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ])
            .send()
            .context("failed to poll GitHub device flow")?
            .error_for_status()
            .context("GitHub token request failed")?
            .json()
            .context("failed to parse GitHub token response")?;

        match response.error.as_deref() {
            Some("authorization_pending") => continue,
            Some("slow_down") => {
                interval = interval.saturating_add(5);
                continue;
            }
            Some("expired_token") => {
                anyhow::bail!("GitHub device code expired; run `fuzzforge auth login` again");
            }
            Some(error) => anyhow::bail!("GitHub device flow failed: {error}"),
            None => {
                let access_token = response
                    .access_token
                    .context("GitHub token response did not include an access token")?;
                let expires_at = response
                    .expires_in
                    .map(|seconds| unix_now().map(|now| now + seconds))
                    .transpose()?;
                let token = StoredGitHubToken {
                    access_token,
                    expires_at,
                };
                save_github_token(&token)?;
                println!("github_auth=ok");
                return Ok(());
            }
        }
    }
}

fn submit_proof(
    api_url: &str,
    wasm_path: &PathBuf,
    record: &HllRecord,
    timeout: Duration,
) -> Result<()> {
    record.validate()?;
    ensure_submit_record_uses_current_verifier(record)?;
    let wasm = fs::read(wasm_path)
        .with_context(|| format!("failed to read WASM module {}", wasm_path.display()))?;
    let github_repository = query_wasm_metadata(&wasm)
        .context("failed to query WASM metadata")?
        .and_then(|metadata| metadata.github_repository);
    let github_token = match github_repository.as_deref() {
        Some(repository) => Some(load_valid_github_token().with_context(|| {
            format!(
                "WASM is associated with GitHub repository {repository}; run `fuzzforge auth login` before submitting"
            )
        })?),
        None => None,
    };
    let client = Client::builder()
        .timeout(timeout)
        .build()
        .context("failed to build HTTP client")?;
    let base = api_url.trim_end_matches('/');
    let wasm_url = format!("{base}/api/programs/{}/wasm", record.program_hash);
    let proof_url = format!("{base}/api/programs/{}/proof", record.program_hash);

    let mut wasm_request = client
        .put(&wasm_url)
        .header(reqwest::header::CONTENT_TYPE, "application/wasm")
        .body(wasm);
    if let Some(token) = github_token {
        wasm_request = wasm_request.bearer_auth(token.access_token);
    }
    let wasm_response = wasm_request
        .send()
        .with_context(|| format!("failed to upload WASM to {wasm_url}"))?;
    ensure_success(wasm_response, "WASM upload")?;

    let proof_response = client
        .post(&proof_url)
        .json(record)
        .send()
        .with_context(|| format!("failed to submit proof to {proof_url}"))?;
    ensure_success(proof_response, "proof submission")?;
    println!(
        "submitted_proof={} stored_observations={}",
        record.program_hash,
        record.observations.len()
    );
    Ok(())
}

fn ensure_submit_record_uses_current_verifier(record: &HllRecord) -> Result<()> {
    let expected = RunConfig::default();
    for observation in &record.observations {
        if observation.config != expected {
            anyhow::bail!(
                "proof submission requires verifier version 1 settings; observation seed {} used a custom config",
                observation.seed_hex
            );
        }
    }
    Ok(())
}

fn ensure_success(response: reqwest::blocking::Response, action: &str) -> Result<()> {
    if response.status().is_success() {
        return Ok(());
    }
    let status = response.status();
    let body = response
        .text()
        .unwrap_or_else(|_| String::from("<unreadable>"));
    anyhow::bail!("{action} failed with HTTP {status}: {body}")
}

fn load_valid_github_token() -> Result<StoredGitHubToken> {
    let path = github_token_path()?;
    let token: StoredGitHubToken = serde_json::from_slice(
        &fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?,
    )
    .with_context(|| format!("failed to parse {}", path.display()))?;
    if let Some(expires_at) = token.expires_at
        && unix_now()? >= expires_at
    {
        anyhow::bail!("stored GitHub token has expired");
    }
    if token.access_token.is_empty() {
        anyhow::bail!("stored GitHub token is empty");
    }
    Ok(token)
}

fn save_github_token(token: &StoredGitHubToken) -> Result<()> {
    let path = github_token_path()?;
    let dir = path
        .parent()
        .context("GitHub token path has no parent directory")?;
    fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;
    let tmp = path.with_extension(format!("json.tmp.{}", std::process::id()));
    fs::write(
        &tmp,
        serde_json::to_vec_pretty(token).context("failed to serialize GitHub token")?,
    )
    .with_context(|| format!("failed to write {}", tmp.display()))?;
    fs::rename(&tmp, &path)
        .with_context(|| format!("failed to rename {} to {}", tmp.display(), path.display()))?;
    Ok(())
}

fn github_token_path() -> Result<PathBuf> {
    let config_home = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(value) => PathBuf::from(value),
        None => std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|home| home.join(".config"))
            .context("HOME is not set; cannot locate GitHub token store")?,
    };
    Ok(config_home.join("fuzzforge").join("github.json"))
}

fn unix_now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs())
}

#[derive(Debug, Deserialize)]
struct GitHubAuthConfig {
    client_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DeviceCodeResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: u64,
    interval: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct GitHubTokenResponse {
    access_token: Option<String>,
    expires_in: Option<u64>,
    error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredGitHubToken {
    access_token: String,
    expires_at: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ProgramListResponse {
    programs: Vec<ProgramSummary>,
    next_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProgramSummary {
    program_hash: String,
    github_repository: Option<String>,
}

struct CorpusDownload {
    program: ProgramSummary,
    wasm_path: PathBuf,
}

fn watch_rate(api_url: &str, window: Duration) -> Result<()> {
    let client = Client::builder()
        .timeout(None)
        .build()
        .context("failed to build HTTP client")?;
    let stream_url = format!("{}/api/hash-results/stream", api_url.trim_end_matches('/'));
    let response = client
        .get(&stream_url)
        .send()
        .with_context(|| format!("failed to connect to {stream_url}"))?;
    ensure_success_ref(&response, "rate stream connection")?;

    let mut tracker = RateTracker::new(window);
    let reader = io::BufReader::new(response);
    for line in io::BufRead::lines(reader) {
        let line = line.context("failed to read rate stream")?;
        let Some(data) = line.strip_prefix("data: ") else {
            continue;
        };
        let event: RateEvent = serde_json::from_str(data).context("failed to parse rate event")?;
        let Some(rate) = tracker.update(event.total_tests, event.timestamp_ms) else {
            continue;
        };
        println!(
            "total_tests={} rate_per_second={:.3}",
            event.total_tests, rate
        );
        io::stdout().flush().context("failed to flush stdout")?;
    }
    Ok(())
}

fn ensure_success_ref(response: &reqwest::blocking::Response, action: &str) -> Result<()> {
    if response.status().is_success() {
        Ok(())
    } else {
        anyhow::bail!("{action} failed with HTTP {}", response.status())
    }
}

#[derive(Debug, Deserialize)]
struct RateEvent {
    total_tests: u64,
    timestamp_ms: u64,
}

struct RateTracker {
    window: Duration,
    samples: std::collections::VecDeque<(u64, u64)>,
}

impl RateTracker {
    fn new(window: Duration) -> Self {
        Self {
            window,
            samples: std::collections::VecDeque::new(),
        }
    }

    fn update(&mut self, total_tests: u64, timestamp_ms: u64) -> Option<f64> {
        self.samples.push_back((timestamp_ms, total_tests));
        let window_ms = self.window.as_millis() as u64;
        while self
            .samples
            .front()
            .is_some_and(|(sample_ms, _)| timestamp_ms.saturating_sub(*sample_ms) > window_ms)
        {
            self.samples.pop_front();
        }
        let (first_ms, first_total) = *self.samples.front()?;
        let elapsed_ms = timestamp_ms.saturating_sub(first_ms);
        if elapsed_ms == 0 {
            return Some(0.0);
        }
        let added = total_tests.saturating_sub(first_total);
        Some(added as f64 / (elapsed_ms as f64 / 1000.0))
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

struct ProgressDisplay {
    proven_before: f64,
    update_in_place: bool,
    proven_added: Arc<atomic_float::AtomicF64>,
    running: Arc<AtomicBool>,
    spinner: Option<JoinHandle<()>>,
    spinner_done: Option<Receiver<()>>,
    finished: bool,
}

impl ProgressDisplay {
    fn start(proven_before: f64, update_in_place: bool) -> Self {
        eprintln!("proven_before={proven_before:.3}");
        let proven_added = Arc::new(atomic_float::AtomicF64::new(0.0));
        let running = Arc::new(AtomicBool::new(update_in_place));
        let (done_tx, done_rx) = mpsc::channel();
        let spinner = if update_in_place {
            Some(spawn_spinner(
                Arc::clone(&proven_added),
                Arc::clone(&running),
                done_tx,
            ))
        } else {
            None
        };
        Self {
            proven_before,
            update_in_place,
            proven_added,
            running,
            spinner,
            spinner_done: Some(done_rx),
            finished: false,
        }
    }

    fn update(&self, estimated_observations: f64) -> Result<()> {
        let proven_added = (estimated_observations - self.proven_before).max(0.0);
        self.proven_added.store(proven_added, Ordering::Relaxed);
        if self.update_in_place {
            Ok(())
        } else {
            self.write_progress(proven_added, true)
        }
    }

    fn finish(&mut self) -> Result<()> {
        self.stop_spinner();
        if self.update_in_place {
            let proven_added = self.proven_added.load(Ordering::Relaxed);
            self.write_progress(proven_added, true)?;
        }
        self.finished = true;
        Ok(())
    }

    fn stop_spinner(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(done) = self.spinner_done.take() {
            let _ = done.recv_timeout(Duration::from_millis(50));
        }
        if self
            .spinner
            .as_ref()
            .is_some_and(|spinner| spinner.is_finished())
            && let Some(spinner) = self.spinner.take()
        {
            let _ = spinner.join();
        }
    }

    fn write_progress(&self, proven_added: f64, newline: bool) -> Result<()> {
        let mut stderr = io::stderr().lock();
        if self.update_in_place {
            write!(stderr, "\rproven_added={proven_added:.3}  ")?;
        } else {
            write!(stderr, "proven_added={proven_added:.3}")?;
        }
        if newline {
            writeln!(stderr)?;
        }
        stderr.flush().context("failed to flush progress output")
    }
}

impl Drop for ProgressDisplay {
    fn drop(&mut self) {
        self.stop_spinner();
        if !self.update_in_place || self.finished {
            return;
        }
        let _ = writeln!(io::stderr().lock());
    }
}

fn spawn_spinner(
    proven_added: Arc<atomic_float::AtomicF64>,
    running: Arc<AtomicBool>,
    done: mpsc::Sender<()>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        const FRAME_INTERVAL: Duration = Duration::from_millis(250);
        const FRAMES: [char; 4] = ['|', '/', '-', '\\'];
        let mut frame_index = 0;
        while running.load(Ordering::Relaxed) {
            let proven_added = proven_added.load(Ordering::Relaxed);
            let mut stderr = io::stderr().lock();
            let _ = write!(
                stderr,
                "\rproven_added={proven_added:.3} {}",
                FRAMES[frame_index]
            );
            let _ = stderr.flush();
            frame_index = (frame_index + 1) % FRAMES.len();
            thread::sleep(FRAME_INTERVAL);
        }
        let _ = done.send(());
    })
}

mod atomic_float {
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Debug)]
    pub struct AtomicF64 {
        bits: AtomicU64,
    }

    impl AtomicF64 {
        pub fn new(value: f64) -> Self {
            Self {
                bits: AtomicU64::new(value.to_bits()),
            }
        }

        pub fn load(&self, order: Ordering) -> f64 {
            f64::from_bits(self.bits.load(order))
        }

        pub fn store(&self, value: f64, order: Ordering) {
            self.bits.store(value.to_bits(), order);
        }
    }
}
