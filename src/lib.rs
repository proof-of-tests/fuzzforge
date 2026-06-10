use std::{
    fmt, fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use wasmi::{
    Caller, Config, Engine, ExternType, Linker, Memory, Module, Store as WasmiStore, StoreLimits,
    StoreLimitsBuilder,
};

pub const HLL_PRECISION: u8 = 6;
pub const HLL_BUCKETS: usize = 1 << HLL_PRECISION;
pub const SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_FUEL: u64 = 10_000_000;
pub const DEFAULT_MEMORY_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_TABLE_ELEMENTS: usize = 10_000;

const WASI_MODULE: &str = "wasi_snapshot_preview1";
const ERR_SUCCESS: i32 = 0;
const ERR_BADF: i32 = 8;
const ERR_FAULT: i32 = 21;
const ERR_INVAL: i32 = 28;
const FD_STDIN: i32 = 0;
const FD_STDOUT: i32 = 1;
const FILETYPE_CHARACTER_DEVICE: u8 = 2;
const RIGHTS_FD_READ: u64 = 1 << 1;
const RIGHTS_FD_FDSTAT_SET_FLAGS: u64 = 1 << 3;
const RIGHTS_FD_WRITE: u64 = 1 << 6;

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub fuel: u64,
    pub memory_bytes: usize,
    pub invoke: Option<String>,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            fuel: DEFAULT_FUEL,
            memory_bytes: DEFAULT_MEMORY_BYTES,
            invoke: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunStatus {
    Success,
    Exit(i32),
    Trap(String),
}

impl fmt::Display for RunStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => f.write_str("success"),
            Self::Exit(code) => write!(f, "exit:{code}"),
            Self::Trap(message) => write!(f, "trap:{message}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub program_hash: String,
    pub stdin_hash: String,
    pub stdout_hash: String,
    pub status: RunStatus,
    pub fuel_consumed: u64,
}

#[derive(Debug, Clone)]
pub struct RunResult {
    pub program_hash: String,
    pub stdin_hash: String,
    pub stdout_hash: String,
    pub status: RunStatus,
    pub fuel_consumed: u64,
    pub fuel_remaining: u64,
    pub stdout: Vec<u8>,
    pub observation_hash: String,
    pub run_count: u64,
    pub estimated_observations: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HllStats {
    pub schema_version: u32,
    pub program_hash: String,
    pub precision: u8,
    pub buckets: usize,
    pub run_count: u64,
    pub last_observation_hash: Option<String>,
    pub estimated_observations: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HllRecord {
    pub schema_version: u32,
    pub program_hash: String,
    pub precision: u8,
    pub run_count: u64,
    pub last_observation_hash: Option<String>,
    pub sketch: Sketch,
}

impl HllRecord {
    pub fn new(program_hash: String) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            program_hash,
            precision: HLL_PRECISION,
            run_count: 0,
            last_observation_hash: None,
            sketch: Sketch::new(),
        }
    }

    pub fn insert_observation(&mut self, observation_hash: &str) -> Result<()> {
        self.validate()?;
        let value = observation_hash_to_u64(observation_hash)?;
        self.sketch.insert_hash(value);
        self.run_count = self.run_count.saturating_add(1);
        self.last_observation_hash = Some(observation_hash.to_owned());
        Ok(())
    }

    pub fn stats(&self) -> HllStats {
        HllStats {
            schema_version: self.schema_version,
            program_hash: self.program_hash.clone(),
            precision: self.precision,
            buckets: 1usize << self.precision,
            run_count: self.run_count,
            last_observation_hash: self.last_observation_hash.clone(),
            estimated_observations: self.sketch.estimate(),
        }
    }

    fn validate(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION {
            bail!("unsupported HLL schema version {}", self.schema_version);
        }
        if self.precision != HLL_PRECISION {
            bail!(
                "unsupported HLL precision {}; fuzzforge only supports p={HLL_PRECISION}",
                self.precision
            );
        }
        self.sketch.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sketch {
    registers: Vec<u8>,
}

impl Sketch {
    pub fn new() -> Self {
        Self {
            registers: vec![0; HLL_BUCKETS],
        }
    }

    pub fn insert_hash(&mut self, hash: u64) {
        debug_assert_eq!(self.registers.len(), HLL_BUCKETS);
        let bucket = (hash >> (u64::BITS - u32::from(HLL_PRECISION))) as usize;
        let remaining = hash << HLL_PRECISION;
        let max_rank = u64::BITS - u32::from(HLL_PRECISION) + 1;
        let rank = if remaining == 0 {
            max_rank
        } else {
            (remaining.leading_zeros() + 1).min(max_rank)
        } as u8;
        self.registers[bucket] = self.registers[bucket].max(rank);
    }

    pub fn estimate(&self) -> f64 {
        let m = HLL_BUCKETS as f64;
        let sum: f64 = self
            .registers
            .iter()
            .map(|rank| 2.0_f64.powi(-i32::from(*rank)))
            .sum();
        let raw = alpha(HLL_BUCKETS) * m * m / sum;
        let zeros = self.registers.iter().filter(|rank| **rank == 0).count();
        if raw <= 2.5 * m && zeros > 0 {
            m * (m / zeros as f64).ln()
        } else {
            raw
        }
    }

    fn validate(&self) -> Result<()> {
        if self.registers.len() != HLL_BUCKETS {
            bail!(
                "invalid HLL register count {}; expected {HLL_BUCKETS}",
                self.registers.len()
            );
        }
        Ok(())
    }
}

impl Default for Sketch {
    fn default() -> Self {
        Self::new()
    }
}

fn alpha(bucket_count: usize) -> f64 {
    match bucket_count {
        16 => 0.673,
        32 => 0.697,
        64 => 0.709,
        count => 0.7213 / (1.0 + 1.079 / count as f64),
    }
}

#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
}

impl Store {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn load_or_new(&self, program_hash: &str) -> Result<HllRecord> {
        let path = self.record_path(program_hash);
        if !path.exists() {
            return Ok(HllRecord::new(program_hash.to_owned()));
        }
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let record: HllRecord = serde_json::from_str(&contents)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        if record.program_hash != program_hash {
            bail!(
                "record hash mismatch: path is {program_hash}, record is {}",
                record.program_hash
            );
        }
        record.validate()?;
        Ok(record)
    }

    pub fn save(&self, record: &HllRecord) -> Result<()> {
        record.validate()?;
        let dir = self.hll_dir();
        fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
        let path = self.record_path(&record.program_hash);
        let tmp = path.with_extension(format!("json.tmp.{}", std::process::id()));
        let bytes = serde_json::to_vec_pretty(record).context("failed to serialize HLL record")?;
        fs::write(&tmp, bytes).with_context(|| format!("failed to write {}", tmp.display()))?;
        fs::rename(&tmp, &path)
            .with_context(|| format!("failed to rename {} to {}", tmp.display(), path.display()))?;
        Ok(())
    }

    pub fn update(&self, program_hash: &str, observation_hash: &str) -> Result<HllStats> {
        let mut record = self.load_or_new(program_hash)?;
        record.insert_observation(observation_hash)?;
        let stats = record.stats();
        self.save(&record)?;
        Ok(stats)
    }

    pub fn stats(&self, program_hash: &str) -> Result<HllStats> {
        let record = self.load_or_new(program_hash)?;
        Ok(record.stats())
    }

    pub fn list(&self) -> Result<Vec<HllStats>> {
        let dir = self.hll_dir();
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut stats = Vec::new();
        for entry in
            fs::read_dir(&dir).with_context(|| format!("failed to read {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|value| value.to_str()) else {
                continue;
            };
            stats.push(self.stats(stem)?);
        }
        stats.sort_by(|left, right| left.program_hash.cmp(&right.program_hash));
        Ok(stats)
    }

    fn hll_dir(&self) -> PathBuf {
        self.root.join("hll")
    }

    fn record_path(&self, program_hash: &str) -> PathBuf {
        self.hll_dir().join(format!("{program_hash}.json"))
    }
}

pub fn hash_bytes_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

pub fn hash_wasm_file(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(hash_bytes_hex(&bytes))
}

pub fn observation_hash(observation: &Observation) -> String {
    let mut hasher = blake3::Hasher::new();
    update_hash_field(&mut hasher, observation.program_hash.as_bytes());
    update_hash_field(&mut hasher, observation.stdin_hash.as_bytes());
    update_hash_field(&mut hasher, observation.stdout_hash.as_bytes());
    update_hash_field(&mut hasher, observation.status.to_string().as_bytes());
    update_hash_field(&mut hasher, &observation.fuel_consumed.to_le_bytes());
    hasher.finalize().to_hex().to_string()
}

pub fn run_wasm(
    wasm_path: &Path,
    stdin: Vec<u8>,
    store_path: &Path,
    config: RunConfig,
) -> Result<RunResult> {
    let wasm = fs::read(wasm_path)
        .with_context(|| format!("failed to read WASM module {}", wasm_path.display()))?;
    run_wasm_bytes(&wasm, stdin, store_path, config)
}

pub fn run_wasm_bytes(
    wasm: &[u8],
    stdin: Vec<u8>,
    store_path: &Path,
    config: RunConfig,
) -> Result<RunResult> {
    let program_hash = hash_bytes_hex(wasm);
    let stdin_hash = hash_bytes_hex(&stdin);
    let output = execute_wasm(wasm, stdin, config)?;
    let stdout_hash = hash_bytes_hex(&output.stdout);
    let observation = Observation {
        program_hash: program_hash.clone(),
        stdin_hash: stdin_hash.clone(),
        stdout_hash: stdout_hash.clone(),
        status: output.status.clone(),
        fuel_consumed: output.fuel_consumed,
    };
    let observation_hash = observation_hash(&observation);
    let stats = Store::new(store_path).update(&program_hash, &observation_hash)?;
    Ok(RunResult {
        program_hash,
        stdin_hash,
        stdout_hash,
        status: output.status,
        fuel_consumed: output.fuel_consumed,
        fuel_remaining: output.fuel_remaining,
        stdout: output.stdout,
        observation_hash,
        run_count: stats.run_count,
        estimated_observations: stats.estimated_observations,
    })
}

#[derive(Debug)]
struct ExecutionOutput {
    status: RunStatus,
    fuel_consumed: u64,
    fuel_remaining: u64,
    stdout: Vec<u8>,
}

#[derive(Debug)]
struct HostState {
    stdin: Vec<u8>,
    stdin_pos: usize,
    stdout: Vec<u8>,
    limits: StoreLimits,
}

fn execute_wasm(wasm: &[u8], stdin: Vec<u8>, config: RunConfig) -> Result<ExecutionOutput> {
    let mut wasmi_config = Config::default();
    wasmi_config.consume_fuel(true);
    let engine = Engine::new(&wasmi_config);
    let module = Module::new(&engine, wasm).context("failed to compile WASM module")?;
    validate_imports(&module)?;

    let limits = StoreLimitsBuilder::new()
        .memory_size(config.memory_bytes)
        .table_elements(DEFAULT_TABLE_ELEMENTS)
        .instances(1)
        .memories(1)
        .tables(1)
        .trap_on_grow_failure(true)
        .build();
    let state = HostState {
        stdin,
        stdin_pos: 0,
        stdout: Vec::new(),
        limits,
    };
    let mut store = WasmiStore::new(&engine, state);
    store.limiter(|state| &mut state.limits);
    store.set_fuel(config.fuel).context("failed to set fuel")?;

    let mut linker = Linker::<HostState>::new(&engine);
    add_wasi_functions(&mut linker)?;
    let instance = linker
        .instantiate_and_start(&mut store, &module)
        .context("failed to instantiate WASM module")?;
    let export = config.invoke.as_deref().unwrap_or("_start");
    let func = instance
        .get_typed_func::<(), ()>(&store, export)
        .with_context(|| format!("missing no-arg export `{export}`"))?;
    let status = match func.call(&mut store, ()) {
        Ok(()) => RunStatus::Success,
        Err(error) => {
            if let Some(code) = error.i32_exit_status() {
                RunStatus::Exit(code)
            } else if let Some(trap_code) = error.as_trap_code() {
                RunStatus::Trap(format!("{trap_code:?}"))
            } else {
                RunStatus::Trap(error.to_string())
            }
        }
    };
    let fuel_remaining = store.get_fuel().context("failed to read remaining fuel")?;
    let stdout = store.data().stdout.clone();
    Ok(ExecutionOutput {
        status,
        fuel_consumed: config.fuel.saturating_sub(fuel_remaining),
        fuel_remaining,
        stdout,
    })
}

fn validate_imports(module: &Module) -> Result<()> {
    for import in module.imports() {
        let module_name = import.module();
        let name = import.name();
        let ExternType::Func(_) = import.ty() else {
            bail!("unsupported import {module_name}::{name}: only functions are allowed");
        };
        if module_name != WASI_MODULE || !is_allowed_wasi_import(name) {
            bail!("unsupported import {module_name}::{name}");
        }
    }
    Ok(())
}

fn is_allowed_wasi_import(name: &str) -> bool {
    matches!(
        name,
        "fd_read"
            | "fd_write"
            | "fd_fdstat_get"
            | "args_sizes_get"
            | "args_get"
            | "environ_sizes_get"
            | "environ_get"
            | "proc_exit"
    )
}

fn add_wasi_functions(linker: &mut Linker<HostState>) -> Result<()> {
    linker.func_wrap(WASI_MODULE, "fd_read", fd_read)?;
    linker.func_wrap(WASI_MODULE, "fd_write", fd_write)?;
    linker.func_wrap(WASI_MODULE, "fd_fdstat_get", fd_fdstat_get)?;
    linker.func_wrap(WASI_MODULE, "args_sizes_get", args_sizes_get)?;
    linker.func_wrap(WASI_MODULE, "args_get", args_get)?;
    linker.func_wrap(WASI_MODULE, "environ_sizes_get", environ_sizes_get)?;
    linker.func_wrap(WASI_MODULE, "environ_get", environ_get)?;
    linker.func_wrap(WASI_MODULE, "proc_exit", proc_exit)?;
    Ok(())
}

fn fd_read(
    mut caller: Caller<'_, HostState>,
    fd: i32,
    iovs: i32,
    iovs_len: i32,
    bytes_read: i32,
) -> i32 {
    if fd != FD_STDIN {
        return ERR_BADF;
    }
    let Some(memory) = guest_memory(&caller) else {
        return ERR_FAULT;
    };
    let iovs = match read_iovs(&memory, &caller, iovs, iovs_len) {
        Ok(iovs) => iovs,
        Err(errno) => return errno,
    };
    let mut total = 0usize;
    for (ptr, len) in iovs {
        let chunk = {
            let state = caller.data_mut();
            let remaining = state.stdin.len().saturating_sub(state.stdin_pos);
            let amount = remaining.min(len);
            let start = state.stdin_pos;
            let end = start + amount;
            state.stdin_pos = end;
            state.stdin[start..end].to_vec()
        };
        if memory.write(&mut caller, ptr, &chunk).is_err() {
            return ERR_FAULT;
        }
        total = total.saturating_add(chunk.len());
        if chunk.len() < len {
            break;
        }
    }
    write_u32(&memory, &mut caller, bytes_read, total as u32)
}

fn fd_write(
    mut caller: Caller<'_, HostState>,
    fd: i32,
    iovs: i32,
    iovs_len: i32,
    bytes_written: i32,
) -> i32 {
    if fd != FD_STDOUT {
        return ERR_BADF;
    }
    let Some(memory) = guest_memory(&caller) else {
        return ERR_FAULT;
    };
    let iovs = match read_iovs(&memory, &caller, iovs, iovs_len) {
        Ok(iovs) => iovs,
        Err(errno) => return errno,
    };
    let mut total = 0usize;
    for (ptr, len) in iovs {
        let mut bytes = vec![0; len];
        if memory.read(&caller, ptr, &mut bytes).is_err() {
            return ERR_FAULT;
        }
        caller.data_mut().stdout.extend_from_slice(&bytes);
        total = total.saturating_add(len);
    }
    write_u32(&memory, &mut caller, bytes_written, total as u32)
}

fn fd_fdstat_get(mut caller: Caller<'_, HostState>, fd: i32, stat_ptr: i32) -> i32 {
    let rights = match fd {
        FD_STDIN => RIGHTS_FD_READ | RIGHTS_FD_FDSTAT_SET_FLAGS,
        FD_STDOUT => RIGHTS_FD_WRITE | RIGHTS_FD_FDSTAT_SET_FLAGS,
        _ => return ERR_BADF,
    };
    let Some(memory) = guest_memory(&caller) else {
        return ERR_FAULT;
    };
    let mut stat = [0u8; 24];
    stat[0] = FILETYPE_CHARACTER_DEVICE;
    stat[2..4].copy_from_slice(&0u16.to_le_bytes());
    stat[8..16].copy_from_slice(&rights.to_le_bytes());
    stat[16..24].copy_from_slice(&0u64.to_le_bytes());
    write_bytes(&memory, &mut caller, stat_ptr, &stat)
}

fn args_sizes_get(mut caller: Caller<'_, HostState>, argc: i32, argv_buf_size: i32) -> i32 {
    let Some(memory) = guest_memory(&caller) else {
        return ERR_FAULT;
    };
    let first = write_u32(&memory, &mut caller, argc, 0);
    if first != ERR_SUCCESS {
        return first;
    }
    write_u32(&memory, &mut caller, argv_buf_size, 0)
}

fn args_get(_caller: Caller<'_, HostState>, _argv: i32, _argv_buf: i32) -> i32 {
    ERR_SUCCESS
}

fn environ_sizes_get(mut caller: Caller<'_, HostState>, envc: i32, env_buf_size: i32) -> i32 {
    let Some(memory) = guest_memory(&caller) else {
        return ERR_FAULT;
    };
    let first = write_u32(&memory, &mut caller, envc, 0);
    if first != ERR_SUCCESS {
        return first;
    }
    write_u32(&memory, &mut caller, env_buf_size, 0)
}

fn environ_get(_caller: Caller<'_, HostState>, _environ: i32, _environ_buf: i32) -> i32 {
    ERR_SUCCESS
}

fn proc_exit(_caller: Caller<'_, HostState>, code: i32) -> Result<(), wasmi::Error> {
    Err(wasmi::Error::i32_exit(code))
}

fn guest_memory(caller: &Caller<'_, HostState>) -> Option<Memory> {
    caller
        .get_export("memory")
        .and_then(|item| item.into_memory())
}

fn read_iovs(
    memory: &Memory,
    caller: &Caller<'_, HostState>,
    iovs: i32,
    iovs_len: i32,
) -> Result<Vec<(usize, usize)>, i32> {
    if !(0..=1_000_000).contains(&iovs_len) {
        return Err(ERR_INVAL);
    }
    let mut result = Vec::with_capacity(iovs_len as usize);
    let mut buf = [0u8; 8];
    for index in 0..iovs_len as usize {
        let offset = ptr_to_usize(iovs).saturating_add(index.saturating_mul(8));
        memory
            .read(caller, offset, &mut buf)
            .map_err(|_| ERR_FAULT)?;
        let ptr = u32::from_le_bytes(buf[0..4].try_into().expect("slice has 4 bytes")) as usize;
        let len = u32::from_le_bytes(buf[4..8].try_into().expect("slice has 4 bytes")) as usize;
        result.push((ptr, len));
    }
    Ok(result)
}

fn write_u32(memory: &Memory, caller: &mut Caller<'_, HostState>, ptr: i32, value: u32) -> i32 {
    write_bytes(memory, caller, ptr, &value.to_le_bytes())
}

fn write_bytes(memory: &Memory, caller: &mut Caller<'_, HostState>, ptr: i32, bytes: &[u8]) -> i32 {
    match memory.write(caller, ptr_to_usize(ptr), bytes) {
        Ok(()) => ERR_SUCCESS,
        Err(_) => ERR_FAULT,
    }
}

fn ptr_to_usize(ptr: i32) -> usize {
    ptr as u32 as usize
}

fn update_hash_field(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn observation_hash_to_u64(hash: &str) -> Result<u64> {
    if hash.len() != 64 {
        bail!("observation hash must be 64 hex characters");
    }
    let bytes = hash.as_bytes();
    let mut value = 0u64;
    for (shift, byte) in bytes.iter().take(16).enumerate() {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => bail!("observation hash contains non-hex byte"),
        };
        value |= u64::from(digit) << ((15 - shift) * 4);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wat_bytes(wat: &str) -> Vec<u8> {
        wat::parse_str(wat).expect("valid wat")
    }

    #[test]
    fn wasm_hash_is_stable() {
        let wasm = wat_bytes(r#"(module (func (export "_start")))"#);
        assert_eq!(hash_bytes_hex(&wasm), hash_bytes_hex(&wasm));
        assert_eq!(hash_bytes_hex(&wasm).len(), 64);
    }

    #[test]
    fn observation_hash_is_stable() {
        let observation = Observation {
            program_hash: "a".repeat(64),
            stdin_hash: "b".repeat(64),
            stdout_hash: "c".repeat(64),
            status: RunStatus::Success,
            fuel_consumed: 42,
        };
        assert_eq!(
            observation_hash(&observation),
            observation_hash(&observation)
        );
    }

    #[test]
    fn hll_precision_is_fixed_at_six() {
        let record = HllRecord::new("a".repeat(64));
        assert_eq!(record.precision, HLL_PRECISION);
        assert_eq!(record.precision, 6);
        assert_eq!(1usize << record.precision, 64);
    }

    #[test]
    fn hll_roundtrips_through_json() {
        let mut record = HllRecord::new("a".repeat(64));
        record
            .insert_observation(&"1".repeat(64))
            .expect("insert observation");
        let json = serde_json::to_string(&record).expect("serialize");
        let restored: HllRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.schema_version, SCHEMA_VERSION);
        assert_eq!(restored.precision, HLL_PRECISION);
        assert_eq!(restored.run_count, 1);
        assert!(restored.stats().estimated_observations >= 1.0);
    }

    #[test]
    fn duplicate_hll_observation_does_not_increase_estimate() {
        let mut record = HllRecord::new("a".repeat(64));
        record
            .insert_observation(&"2".repeat(64))
            .expect("first insert");
        let first = record.stats().estimated_observations;
        record
            .insert_observation(&"2".repeat(64))
            .expect("second insert");
        let second = record.stats().estimated_observations;
        assert_eq!(record.run_count, 2);
        assert_eq!(first, second);
    }

    #[test]
    fn distinct_hll_observations_increase_estimate() {
        let mut record = HllRecord::new("a".repeat(64));
        record
            .insert_observation(&"2".repeat(64))
            .expect("first insert");
        let first = record.stats().estimated_observations;
        record
            .insert_observation(&"3".repeat(64))
            .expect("second insert");
        let second = record.stats().estimated_observations;
        assert_eq!(record.run_count, 2);
        assert!(second > first);
    }

    #[test]
    fn hll_register_count_is_validated() {
        let mut record = HllRecord::new("a".repeat(64));
        record.sketch.registers.pop();
        let err = record.validate().unwrap_err();
        assert!(err.to_string().contains("register count"));
    }

    #[test]
    fn echo_module_reads_stdin_and_writes_stdout() {
        let wasm = wat_bytes(
            r#"
            (module
              (import "wasi_snapshot_preview1" "fd_read"
                (func $fd_read (param i32 i32 i32 i32) (result i32)))
              (import "wasi_snapshot_preview1" "fd_write"
                (func $fd_write (param i32 i32 i32 i32) (result i32)))
              (memory (export "memory") 1)
              (func (export "_start")
                (i32.store (i32.const 0) (i32.const 16))
                (i32.store (i32.const 4) (i32.const 5))
                (drop (call $fd_read
                  (i32.const 0) (i32.const 0) (i32.const 1) (i32.const 24)))
                (i32.store (i32.const 8) (i32.const 16))
                (i32.store (i32.const 12) (i32.load (i32.const 24)))
                (drop (call $fd_write
                  (i32.const 1) (i32.const 8) (i32.const 1) (i32.const 28)))))
            "#,
        );
        let output = execute_wasm(&wasm, b"hello".to_vec(), RunConfig::default()).unwrap();
        assert_eq!(output.status, RunStatus::Success);
        assert_eq!(output.stdout, b"hello");
    }

    #[test]
    fn args_and_env_are_empty() {
        let wasm = wat_bytes(
            r#"
            (module
              (import "wasi_snapshot_preview1" "args_sizes_get"
                (func $args_sizes_get (param i32 i32) (result i32)))
              (import "wasi_snapshot_preview1" "environ_sizes_get"
                (func $environ_sizes_get (param i32 i32) (result i32)))
              (memory (export "memory") 1)
              (func (export "_start")
                (drop (call $args_sizes_get (i32.const 0) (i32.const 4)))
                (drop (call $environ_sizes_get (i32.const 8) (i32.const 12)))
                (if (i32.or
                    (i32.or (i32.load (i32.const 0)) (i32.load (i32.const 4)))
                    (i32.or (i32.load (i32.const 8)) (i32.load (i32.const 12))))
                  (then unreachable))))
            "#,
        );
        let output = execute_wasm(&wasm, Vec::new(), RunConfig::default()).unwrap();
        assert_eq!(output.status, RunStatus::Success);
    }

    #[test]
    fn proc_exit_is_reported_deterministically() {
        let wasm = wat_bytes(
            r#"
            (module
              (import "wasi_snapshot_preview1" "proc_exit"
                (func $proc_exit (param i32)))
              (func (export "_start")
                (call $proc_exit (i32.const 7))))
            "#,
        );
        let output = execute_wasm(&wasm, Vec::new(), RunConfig::default()).unwrap();
        assert_eq!(output.status, RunStatus::Exit(7));
    }

    #[test]
    fn random_import_is_rejected() {
        let wasm = wat_bytes(
            r#"
            (module
              (import "wasi_snapshot_preview1" "random_get"
                (func $random_get (param i32 i32) (result i32)))
              (func (export "_start")))
            "#,
        );
        let err = execute_wasm(&wasm, Vec::new(), RunConfig::default()).unwrap_err();
        assert!(err.to_string().contains("random_get"));
    }

    #[test]
    fn clock_import_is_rejected() {
        let wasm = wat_bytes(
            r#"
            (module
              (import "wasi_snapshot_preview1" "clock_time_get"
                (func $clock_time_get (param i32 i64 i32) (result i32)))
              (func (export "_start")))
            "#,
        );
        let err = execute_wasm(&wasm, Vec::new(), RunConfig::default()).unwrap_err();
        assert!(err.to_string().contains("clock_time_get"));
    }

    #[test]
    fn filesystem_import_is_rejected() {
        let wasm = wat_bytes(
            r#"
            (module
              (import "wasi_snapshot_preview1" "path_open"
                (func $path_open
                  (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
              (func (export "_start")))
            "#,
        );
        let err = execute_wasm(&wasm, Vec::new(), RunConfig::default()).unwrap_err();
        assert!(err.to_string().contains("path_open"));
    }

    #[test]
    fn stderr_write_gets_deterministic_badf() {
        let wasm = wat_bytes(
            r#"
            (module
              (import "wasi_snapshot_preview1" "fd_write"
                (func $fd_write (param i32 i32 i32 i32) (result i32)))
              (memory (export "memory") 1)
              (func (export "_start")
                (i32.store (i32.const 0) (i32.const 16))
                (i32.store (i32.const 4) (i32.const 1))
                (i32.store8 (i32.const 16) (i32.const 120))
                (if (i32.ne
                    (call $fd_write (i32.const 2) (i32.const 0) (i32.const 1) (i32.const 8))
                    (i32.const 8))
                  (then unreachable))))
            "#,
        );
        let output = execute_wasm(&wasm, Vec::new(), RunConfig::default()).unwrap();
        assert_eq!(output.status, RunStatus::Success);
        assert!(output.stdout.is_empty());
    }

    #[test]
    fn fuel_exhaustion_is_reported_as_trap() {
        let wasm = wat_bytes(
            r#"
            (module
              (func (export "_start")
                (loop $again
                  br $again)))
            "#,
        );
        let output = execute_wasm(
            &wasm,
            Vec::new(),
            RunConfig {
                fuel: 1_000,
                ..RunConfig::default()
            },
        )
        .unwrap();
        assert_eq!(output.status, RunStatus::Trap("OutOfFuel".to_owned()));
    }

    #[test]
    fn memory_limit_blocks_instantiation() {
        let wasm = wat_bytes(r#"(module (memory 2) (func (export "_start")))"#);
        let err = execute_wasm(
            &wasm,
            Vec::new(),
            RunConfig {
                memory_bytes: 64 * 1024,
                ..RunConfig::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("instantiate"));
    }
}
