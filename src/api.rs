use std::{
    fs,
    path::PathBuf,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use fuzzforge::{HllRecord, StoredObservation, hash_bytes_hex, query_wasm_metadata};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};

pub(crate) const DEFAULT_SUBMIT_TIMEOUT_SECONDS: u64 = 30;
pub(crate) const DEFAULT_API_URL: &str = "https://fuzzforge.lemmih.com";
const API_URL_ENV: &str = "FUZZFORGE_API_URL";

pub(crate) fn api_url_or_env(api_url: Option<String>) -> Result<String> {
    match api_url {
        Some(api_url) => Ok(api_url),
        None => Ok(std::env::var(API_URL_ENV).unwrap_or_else(|_| DEFAULT_API_URL.to_string())),
    }
}

pub(crate) fn github_auth_login(api_url: &str, timeout: Duration) -> Result<()> {
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

pub(crate) fn upload_wasm(api_url: &str, wasm_path: &PathBuf, timeout: Duration) -> Result<()> {
    let wasm = fs::read(wasm_path)
        .with_context(|| format!("failed to read WASM module {}", wasm_path.display()))?;
    let program_hash = hash_bytes_hex(&wasm);
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
    let wasm_url = format!("{base}/api/programs/{program_hash}/wasm");

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
    println!("uploaded_wasm={program_hash}");
    Ok(())
}

pub(crate) fn submit_proof(api_url: &str, record: &HllRecord, timeout: Duration) -> Result<()> {
    record.validate()?;
    ensure_submit_record_uses_current_verifier(record)?;
    let observations: Vec<_> = record.bucket_witnesses().collect();
    if observations.is_empty() {
        anyhow::bail!("proof submission record has no observations");
    }
    let client = Client::builder()
        .timeout(timeout)
        .build()
        .context("failed to build HTTP client")?;
    let base = api_url.trim_end_matches('/');
    let proof_url = format!("{base}/api/programs/{}/proof", record.program_hash);
    for observation in &observations {
        submit_observation(&client, &proof_url, observation)?;
    }
    println!(
        "submitted_proof={} stored_observations={}",
        record.program_hash,
        observations.len()
    );
    Ok(())
}

pub(crate) fn submit_proof_record(
    client: &Client,
    api_url: &str,
    record: &HllRecord,
) -> Result<()> {
    record.validate()?;
    ensure_submit_record_uses_current_verifier(record)?;
    let observations: Vec<_> = record.bucket_witnesses().collect();
    if observations.len() != 1 {
        anyhow::bail!(
            "proof submission record must contain exactly one observation; found {}",
            observations.len()
        );
    }
    let proof_url = format!(
        "{}/api/programs/{}/proof",
        api_url.trim_end_matches('/'),
        record.program_hash
    );
    let observation = observations[0];
    submit_observation(client, &proof_url, observation)?;
    println!(
        "submitted_observation={} stored_observations={}",
        observation.observation_hash,
        record.bucket_witnesses().count()
    );
    Ok(())
}

pub(crate) fn submit_bug_seed(
    api_url: &str,
    program_hash: &str,
    seed_hex: &str,
    timeout: Duration,
) -> Result<()> {
    let client = Client::builder()
        .timeout(timeout)
        .build()
        .context("failed to build HTTP client")?;
    submit_bug_seed_record(&client, api_url, program_hash, seed_hex)
}

pub(crate) fn submit_bug_seed_record(
    client: &Client,
    api_url: &str,
    program_hash: &str,
    seed_hex: &str,
) -> Result<()> {
    let bug_url = format!(
        "{}/api/programs/{program_hash}/bugs",
        api_url.trim_end_matches('/')
    );
    let bug_seed = BugSeedSubmission {
        seed_hex,
        verifier_version: 1,
    };
    let response = client
        .post(&bug_url)
        .json(&bug_seed)
        .send()
        .with_context(|| format!("failed to submit bug seed to {bug_url}"))?;
    ensure_success(response, "bug seed submission")?;
    println!("submitted_bug_seed={program_hash} seed={seed_hex}");
    Ok(())
}

fn submit_observation(
    client: &Client,
    proof_url: &str,
    observation: &StoredObservation,
) -> Result<()> {
    let response = client
        .post(proof_url)
        .json(observation)
        .send()
        .with_context(|| format!("failed to submit proof to {proof_url}"))?;
    ensure_success(response, "proof submission")
}

pub(crate) fn ensure_success_ref(
    response: &reqwest::blocking::Response,
    action: &str,
) -> Result<()> {
    if response.status().is_success() {
        Ok(())
    } else {
        anyhow::bail!("{action} failed with HTTP {}", response.status())
    }
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

fn ensure_submit_record_uses_current_verifier(record: &HllRecord) -> Result<()> {
    for observation in record.bucket_witnesses() {
        if observation.verifier_version != 1 {
            anyhow::bail!(
                "proof submission requires verifier version 1 settings; observation seed {} used verifier version {}",
                observation.seed_hex,
                observation.verifier_version
            );
        }
    }
    Ok(())
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

#[derive(Debug, Serialize)]
struct BugSeedSubmission<'a> {
    seed_hex: &'a str,
    verifier_version: u32,
}
