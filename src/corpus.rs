use std::{collections::HashMap, fs, io, path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use fuzzforge::{
    DEFAULT_SEED_BYTES, HLL_PRECISION, HllRecord, RunConfig, RunSession, StoredObservation,
    generate_seed, hash_bytes_hex, query_wasm_metadata,
};
use reqwest::blocking::Client;
use serde::Deserialize;

use crate::api::{ensure_success_ref, submit_bug_seed_record, submit_proof_record};

pub(crate) const DEFAULT_CORPUS_FUEL_BUDGET: u64 = 10_000_000_000;
const PROGRAM_LIST_PAGE_SIZE: usize = 100;

pub(crate) fn run_corpus(api_url: &str, fuel_budget: u64, timeout: Duration) -> Result<()> {
    let client = Client::builder()
        .timeout(timeout)
        .build()
        .context("failed to build HTTP client")?;
    let cache_dir = wasm_cache_dir()?;
    let mut completed_passes = 0usize;
    loop {
        let programs = list_associated_programs(&client, api_url)?;
        eprintln!(
            "corpus_pass={} associated_programs={}",
            completed_passes + 1,
            programs.len()
        );
        for program in programs {
            match load_cached_associated_program(&client, api_url, &cache_dir, program) {
                Ok(Some(download)) => run_corpus_program(api_url, &client, &download, fuel_budget)
                    .with_context(|| format!("failed to run {}", download.program.program_hash))?,
                Ok(None) => {}
                Err(error) => eprintln!("download_error={error:#}"),
            }
        }
        completed_passes = completed_passes.saturating_add(1);
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

fn load_cached_associated_program(
    client: &Client,
    api_url: &str,
    cache_dir: &PathBuf,
    program: ProgramSummary,
) -> Result<Option<CorpusDownload>> {
    let wasm_path = cache_dir.join(format!("{}.wasm", program.program_hash));
    let wasm = match fs::read(&wasm_path) {
        Ok(wasm) => wasm,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            download_wasm_to_cache(client, api_url, cache_dir, &program)?
        }
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", wasm_path.display()));
        }
    };

    let actual_hash = hash_bytes_hex(&wasm);
    if actual_hash == program.program_hash {
        return validate_cached_associated_program(program, wasm);
    }

    eprintln!(
        "cache_hash_mismatch={} path={}",
        program.program_hash,
        wasm_path.display()
    );
    let wasm = download_wasm_to_cache(client, api_url, cache_dir, &program)?;
    validate_cached_associated_program(program, wasm)
}

fn download_wasm_to_cache(
    client: &Client,
    api_url: &str,
    cache_dir: &PathBuf,
    program: &ProgramSummary,
) -> Result<Vec<u8>> {
    let base = api_url.trim_end_matches('/');
    let wasm_url = format!("{base}/api/programs/{}/wasm", program.program_hash);
    let response = client
        .get(&wasm_url)
        .send()
        .with_context(|| format!("failed to download WASM from {wasm_url}"))?;
    ensure_success_ref(&response, "WASM download")?;
    let wasm = response.bytes().context("failed to read WASM download")?;
    let actual_hash = hash_bytes_hex(&wasm);
    if actual_hash != program.program_hash {
        anyhow::bail!(
            "downloaded WASM hash mismatch: expected {}, got {}",
            program.program_hash,
            actual_hash
        );
    }
    fs::create_dir_all(cache_dir)
        .with_context(|| format!("failed to create {}", cache_dir.display()))?;
    let wasm_path = cache_dir.join(format!("{}.wasm", program.program_hash));
    let tmp = wasm_path.with_extension(format!("wasm.tmp.{}", std::process::id()));
    fs::write(&tmp, &wasm).with_context(|| format!("failed to write {}", tmp.display()))?;
    fs::rename(&tmp, &wasm_path).with_context(|| {
        format!(
            "failed to rename {} to {}",
            tmp.display(),
            wasm_path.display()
        )
    })?;
    Ok(wasm.to_vec())
}

fn validate_cached_associated_program(
    program: ProgramSummary,
    wasm: Vec<u8>,
) -> Result<Option<CorpusDownload>> {
    let metadata =
        query_wasm_metadata(&wasm).context("failed to query downloaded WASM metadata")?;
    if metadata
        .and_then(|metadata| metadata.github_repository)
        .is_none()
    {
        eprintln!("skipped_unassociated={}", program.program_hash);
        return Ok(None);
    }
    Ok(Some(CorpusDownload { program, wasm }))
}

fn run_corpus_program(
    api_url: &str,
    client: &Client,
    download: &CorpusDownload,
    fuel_budget: u64,
) -> Result<()> {
    let CentralState {
        record: initial_record,
        mut bucket_witnesses,
    } = fetch_central_state(client, api_url, &download.program.program_hash)?;
    let mut session = RunSession::from_wasm_bytes_with_record(
        &download.wasm,
        initial_record,
        RunConfig::default(),
    )
    .with_context(|| format!("failed to prepare {}", download.program.program_hash))?;
    let mut fuel_spent = 0u64;
    let mut uploaded_observations = 0u64;
    let mut skipped_observations = 0u64;
    let mut uploaded_bug_seeds = 0u64;
    eprintln!(
        "program_start={} repository={} fuel_budget={} initial_estimate={:.3}",
        download.program.program_hash,
        download.program.github_repository.as_deref().unwrap_or("-"),
        fuel_budget,
        session.stats().estimated_observations
    );
    while fuel_spent < fuel_budget {
        let result = session
            .run(generate_seed(DEFAULT_SEED_BYTES)?)
            .with_context(|| format!("failed to run {}", download.program.program_hash))?;
        fuel_spent = fuel_spent.saturating_add(result.fuel_consumed);
        if result.bug_found {
            submit_bug_seed_record(client, api_url, session.program_hash(), &result.seed_hex)?;
            uploaded_bug_seeds = uploaded_bug_seeds.saturating_add(1);
            eprintln!(
                "bug_seed={} seed={} stderr_bytes={}",
                session.program_hash(),
                result.seed_hex,
                result.stderr.len()
            );
            continue;
        }
        let proof = single_observation_record(
            session.program_hash(),
            result.seed_hex.clone(),
            result.observation_hash.clone(),
        )?;
        let observation_hash = &result.observation_hash;
        let bucket = observation_bucket(observation_hash)?;
        if !observation_improves_bucket(&bucket_witnesses, bucket, observation_hash) {
            skipped_observations = skipped_observations.saturating_add(1);
        } else {
            submit_proof_record(client, api_url, &proof)?;
            bucket_witnesses.insert(bucket, observation_hash.clone());
            uploaded_observations = uploaded_observations.saturating_add(1);
        }
        if result.fuel_consumed == 0 {
            eprintln!("program_zero_fuel={}", session.program_hash());
            break;
        }
    }
    eprintln!(
        "program_done={} fuel_spent={} uploaded_observations={} skipped_observations={} uploaded_bug_seeds={} estimated_observations={:.3}",
        session.program_hash(),
        fuel_spent,
        uploaded_observations,
        skipped_observations,
        uploaded_bug_seeds,
        session.stats().estimated_observations
    );
    Ok(())
}

fn fetch_central_state(client: &Client, api_url: &str, program_hash: &str) -> Result<CentralState> {
    let proof_url = format!(
        "{}/api/programs/{program_hash}/proof",
        api_url.trim_end_matches('/')
    );
    let response = client
        .get(&proof_url)
        .send()
        .with_context(|| format!("failed to fetch central proof from {proof_url}"))?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(CentralState {
            record: HllRecord::new(program_hash.to_owned()),
            bucket_witnesses: HashMap::new(),
        });
    }
    ensure_success_ref(&response, "central proof fetch")?;
    let proof: CentralProof = response.json().context("failed to parse central proof")?;
    if proof.program_hash != program_hash {
        anyhow::bail!(
            "central proof hash mismatch: expected {}, got {}",
            program_hash,
            proof.program_hash
        );
    }
    if proof.schema_version != 2 {
        anyhow::bail!("unsupported central proof schema {}", proof.schema_version);
    }
    if proof.precision != 6 {
        anyhow::bail!("unsupported central proof precision {}", proof.precision);
    }
    let mut bucket_witnesses = HashMap::new();
    for observation in proof.buckets.iter().filter_map(Option::as_ref) {
        let bucket = observation_bucket(&observation.observation_hash)?;
        if observation_improves_bucket(&bucket_witnesses, bucket, &observation.observation_hash) {
            bucket_witnesses.insert(bucket, observation.observation_hash.clone());
        }
    }
    let record = HllRecord {
        schema_version: proof.schema_version,
        program_hash: proof.program_hash,
        precision: proof.precision,
        buckets: proof.buckets,
    };
    record.validate()?;
    Ok(CentralState {
        record,
        bucket_witnesses,
    })
}

fn observation_improves_bucket(
    bucket_witnesses: &HashMap<usize, String>,
    bucket: usize,
    observation_hash: &str,
) -> bool {
    bucket_witnesses
        .get(&bucket)
        .is_none_or(|previous| observation_hash < previous.as_str())
}

fn single_observation_record(
    program_hash: &str,
    seed_hex: String,
    observation_hash: String,
) -> Result<HllRecord> {
    let observation = StoredObservation {
        seed_hex,
        verifier_version: 1,
        observation_hash,
    };
    let mut proof = HllRecord::new(program_hash.to_owned());
    proof.insert_observation(observation)?;
    Ok(proof)
}

fn observation_bucket(observation_hash: &str) -> Result<usize> {
    if observation_hash.len() < 16
        || !observation_hash
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        anyhow::bail!("invalid observation hash `{observation_hash}`");
    }
    let value = u64::from_str_radix(&observation_hash[..16], 16)
        .with_context(|| format!("failed to parse observation hash `{observation_hash}`"))?;
    Ok((value >> (u64::BITS - u32::from(HLL_PRECISION))) as usize)
}

fn wasm_cache_dir() -> Result<PathBuf> {
    let cache_home = match std::env::var_os("XDG_CACHE_HOME") {
        Some(value) => PathBuf::from(value),
        None => std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|home| home.join(".cache"))
            .context("HOME is not set; cannot locate WASM cache directory")?,
    };
    Ok(cache_home.join("fuzzforge").join("wasm"))
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

struct CentralState {
    record: HllRecord,
    bucket_witnesses: HashMap<usize, String>,
}

#[derive(Debug, Deserialize)]
struct CentralProof {
    schema_version: u32,
    program_hash: String,
    precision: u8,
    buckets: Vec<Option<StoredObservation>>,
}

struct CorpusDownload {
    program: ProgramSummary,
    wasm: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::observation_improves_bucket;

    #[test]
    fn corpus_only_submits_observations_that_improve_their_bucket() {
        let mut bucket_witnesses = HashMap::new();
        bucket_witnesses.insert(1, "b".to_owned());

        assert!(observation_improves_bucket(&bucket_witnesses, 0, "c"));
        assert!(observation_improves_bucket(&bucket_witnesses, 1, "a"));
        assert!(!observation_improves_bucket(&bucket_witnesses, 1, "b"));
        assert!(!observation_improves_bucket(&bucket_witnesses, 1, "c"));
    }
}
