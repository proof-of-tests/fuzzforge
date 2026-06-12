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
    time::Duration,
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use fuzzforge::{
    DEFAULT_FUEL, DEFAULT_MEMORY_BYTES, DEFAULT_SAVE_FUEL_INTERVAL, DEFAULT_SEED_BYTES, HllRecord,
    RunConfig, RunSession, Store, generate_seed, hash_wasm_file, seed_from_hex, verify_wasm,
};
use reqwest::blocking::Client;
use serde::Deserialize;

const DEFAULT_RUN_COUNT: usize = 1;
const DEFAULT_SUBMIT_TIMEOUT_SECONDS: u64 = 30;
const DEFAULT_RATE_WINDOW_SECONDS: u64 = 10;
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

fn api_url_or_env(api_url: Option<String>) -> Result<String> {
    match api_url {
        Some(api_url) => Ok(api_url),
        None => Ok(std::env::var(API_URL_ENV).unwrap_or_else(|_| DEFAULT_API_URL.to_string())),
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
    let client = Client::builder()
        .timeout(timeout)
        .build()
        .context("failed to build HTTP client")?;
    let base = api_url.trim_end_matches('/');
    let wasm_url = format!("{base}/api/programs/{}/wasm", record.program_hash);
    let proof_url = format!("{base}/api/programs/{}/proof", record.program_hash);

    let wasm_response = client
        .put(&wasm_url)
        .header(reqwest::header::CONTENT_TYPE, "application/wasm")
        .body(wasm)
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
