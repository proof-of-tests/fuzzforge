use std::{fmt, slice};

use serde::{Deserialize, Serialize};
use wasmi::{
    Caller, Config, Engine, ExternType, Linker, Memory, Module, Store as WasmiStore, StoreLimits,
    StoreLimitsBuilder,
};

const HLL_PRECISION: u8 = 6;
const HLL_BUCKETS: usize = 1 << HLL_PRECISION;
const SUPPORTED_VERIFIER_VERSIONS: [u32; 1] = [1];
const DEFAULT_FUEL: u64 = 10_000_000;
const DEFAULT_MEMORY_BYTES: usize = 64 * 1024 * 1024;
const WASI_MODULE: &str = "wasi_snapshot_preview1";
const REPOSITORY_QUERY_ARGS: [&[u8]; 2] = [b"fuzzforge", b"--repository"];
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
const DEFAULT_TABLE_ELEMENTS: usize = 10_000;

const VERIFY_OK: i32 = 0;
const VERIFY_INVALID_INPUT: i32 = 1;
const VERIFY_INVALID_RECORD: i32 = 2;
const VERIFY_WASM_MISMATCH: i32 = 3;
const VERIFY_OBSERVATION_MISMATCH: i32 = 4;
const VERIFY_UNSUPPORTED_WASM: i32 = 5;
const VERIFY_HASH_MISMATCH: i32 = 9;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunConfig {
    pub fuel: u64,
    pub memory_bytes: usize,
    pub invoke: Option<String>,
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

#[derive(Debug, Deserialize)]
pub struct HllRecord {
    pub schema_version: u32,
    pub program_hash: String,
    pub precision: u8,
    pub sketch: Sketch,
    pub observations: Vec<StoredObservation>,
}

#[derive(Debug, Deserialize)]
pub struct Sketch {
    registers: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredObservation {
    pub seed_hex: String,
    pub observation_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Observation {
    program_hash: String,
    seed_hex: String,
    stdout_hash: String,
    status: RunStatus,
    fuel_consumed: u64,
    config: RunConfig,
}

#[derive(Debug)]
struct ExecutionOutput {
    status: RunStatus,
    fuel_consumed: u64,
    stdout: Vec<u8>,
}

#[derive(Debug)]
struct HostState {
    args: Vec<Vec<u8>>,
    stdin: Vec<u8>,
    stdin_pos: usize,
    stdout: Vec<u8>,
    limits: StoreLimits,
}

struct WasmProgram {
    program_hash: String,
    engine: Engine,
    module: Module,
    linker: Linker<HostState>,
}

#[unsafe(no_mangle)]
pub extern "C" fn ff_alloc(len: usize) -> *mut u8 {
    let mut bytes = Vec::with_capacity(len);
    let ptr = bytes.as_mut_ptr();
    std::mem::forget(bytes);
    ptr
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ff_dealloc(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        drop(unsafe { Vec::from_raw_parts(ptr, 0, len) });
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ff_hash_hex(
    wasm_ptr: *const u8,
    wasm_len: usize,
    out_ptr: *mut u8,
    out_len: usize,
) -> i32 {
    if wasm_ptr.is_null() || out_ptr.is_null() || out_len < 64 {
        return VERIFY_INVALID_INPUT;
    }
    let wasm = unsafe { slice::from_raw_parts(wasm_ptr, wasm_len) };
    let out = unsafe { slice::from_raw_parts_mut(out_ptr, out_len) };
    out[..64].copy_from_slice(hash_bytes_hex(wasm).as_bytes());
    VERIFY_OK
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ff_repository(
    wasm_ptr: *const u8,
    wasm_len: usize,
    out_ptr: *mut u8,
    out_len: usize,
) -> i32 {
    if wasm_ptr.is_null() || out_ptr.is_null() {
        return -VERIFY_INVALID_INPUT;
    }
    let wasm = unsafe { slice::from_raw_parts(wasm_ptr, wasm_len) };
    let out = unsafe { slice::from_raw_parts_mut(out_ptr, out_len) };
    match query_repository(wasm) {
        Ok(None) => VERIFY_OK,
        Ok(Some(repository)) => {
            let bytes = repository.as_bytes();
            if bytes.len() > out.len() {
                return -VERIFY_INVALID_INPUT;
            }
            out[..bytes.len()].copy_from_slice(bytes);
            bytes.len() as i32
        }
        Err(code) => -code,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ff_verify(
    wasm_ptr: *const u8,
    wasm_len: usize,
    record_ptr: *const u8,
    record_len: usize,
) -> i32 {
    if wasm_ptr.is_null() || record_ptr.is_null() {
        return VERIFY_INVALID_INPUT;
    }
    let wasm = unsafe { slice::from_raw_parts(wasm_ptr, wasm_len) };
    let record_json = unsafe { slice::from_raw_parts(record_ptr, record_len) };
    match verify(wasm, record_json) {
        Ok(()) => VERIFY_OK,
        Err(code) => code,
    }
}

fn verify(wasm: &[u8], record_json: &[u8]) -> Result<(), i32> {
    let record: HllRecord =
        serde_json::from_slice(record_json).map_err(|_| VERIFY_INVALID_RECORD)?;
    if record.schema_version != 2
        || record.precision != HLL_PRECISION
        || record.sketch.registers.len() != HLL_BUCKETS
        || record.observations.is_empty()
    {
        return Err(VERIFY_INVALID_RECORD);
    }

    let program = WasmProgram::compile(wasm).map_err(|_| VERIFY_UNSUPPORTED_WASM)?;
    if record.program_hash != program.program_hash {
        return Err(VERIFY_WASM_MISMATCH);
    }

    for expected in &record.observations {
        verify_observation(&program, &record.program_hash, expected)?;
    }
    Ok(())
}

fn query_repository(wasm: &[u8]) -> Result<Option<String>, i32> {
    let program = WasmProgram::compile(wasm).map_err(|_| VERIFY_UNSUPPORTED_WASM)?;
    let output = program
        .execute_with_args(
            Vec::new(),
            verifier_version_config(1),
            REPOSITORY_QUERY_ARGS
                .iter()
                .map(|arg| arg.to_vec())
                .collect(),
        )
        .map_err(|_| VERIFY_OBSERVATION_MISMATCH)?;
    if output.status != RunStatus::Success {
        return Ok(None);
    }
    let repository = std::str::from_utf8(&output.stdout)
        .map_err(|_| VERIFY_INVALID_RECORD)?
        .trim();
    if repository.is_empty() {
        return Ok(None);
    }
    Ok(Some(repository.to_owned()))
}

impl WasmProgram {
    fn compile(wasm: &[u8]) -> Result<Self, ()> {
        let program_hash = hash_bytes_hex(wasm);
        let mut wasmi_config = Config::default();
        wasmi_config.consume_fuel(true);
        let engine = Engine::new(&wasmi_config);
        let module = Module::new(&engine, wasm).map_err(|_| ())?;
        validate_imports(&module)?;

        let mut linker = Linker::<HostState>::new(&engine);
        add_wasi_functions(&mut linker)?;
        Ok(Self {
            program_hash,
            engine,
            module,
            linker,
        })
    }

    fn execute(&self, stdin: Vec<u8>, config: RunConfig) -> Result<ExecutionOutput, ()> {
        self.execute_with_args(stdin, config, Vec::new())
    }

    fn execute_with_args(
        &self,
        stdin: Vec<u8>,
        config: RunConfig,
        args: Vec<Vec<u8>>,
    ) -> Result<ExecutionOutput, ()> {
        let limits = StoreLimitsBuilder::new()
            .memory_size(config.memory_bytes)
            .table_elements(DEFAULT_TABLE_ELEMENTS)
            .instances(1)
            .memories(1)
            .tables(1)
            .trap_on_grow_failure(true)
            .build();
        let state = HostState {
            args,
            stdin,
            stdin_pos: 0,
            stdout: Vec::new(),
            limits,
        };
        let mut store = WasmiStore::new(&self.engine, state);
        store.limiter(|state| &mut state.limits);
        store.set_fuel(config.fuel).map_err(|_| ())?;

        let instance = self
            .linker
            .instantiate_and_start(&mut store, &self.module)
            .map_err(|_| ())?;
        let export = config.invoke.as_deref().unwrap_or("_start");
        let func = instance
            .get_typed_func::<(), ()>(&store, export)
            .map_err(|_| ())?;
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
        let fuel_remaining = store.get_fuel().map_err(|_| ())?;
        let stdout = std::mem::take(&mut store.data_mut().stdout);
        Ok(ExecutionOutput {
            status,
            fuel_consumed: config.fuel.saturating_sub(fuel_remaining),
            stdout,
        })
    }
}

fn verify_observation(
    program: &WasmProgram,
    program_hash: &str,
    expected: &StoredObservation,
) -> Result<(), i32> {
    let seed = seed_from_hex(&expected.seed_hex).ok_or(VERIFY_INVALID_RECORD)?;
    for version in SUPPORTED_VERIFIER_VERSIONS {
        let config = verifier_version_config(version);
        let output = program
            .execute(seed.clone(), config.clone())
            .map_err(|_| VERIFY_OBSERVATION_MISMATCH)?;
        let stdout_hash = hash_bytes_hex(&output.stdout);
        let actual = StoredObservation::from_observation(Observation {
            program_hash: program_hash.to_owned(),
            seed_hex: expected.seed_hex.clone(),
            stdout_hash,
            status: output.status,
            fuel_consumed: output.fuel_consumed,
            config,
        });
        if actual.observation_hash == expected.observation_hash {
            return Ok(());
        }
    }
    Err(VERIFY_HASH_MISMATCH)
}

fn verifier_version_config(version: u32) -> RunConfig {
    match version {
        1 => RunConfig {
            fuel: DEFAULT_FUEL,
            memory_bytes: DEFAULT_MEMORY_BYTES,
            invoke: None,
        },
        _ => unreachable!("unsupported verifier version"),
    }
}

impl StoredObservation {
    fn from_observation(observation: Observation) -> Self {
        let observation_hash = observation_hash(&observation);
        Self {
            seed_hex: observation.seed_hex,
            observation_hash,
        }
    }
}

fn validate_imports(module: &Module) -> Result<(), ()> {
    for import in module.imports() {
        let module_name = import.module();
        let name = import.name();
        let ExternType::Func(_) = import.ty() else {
            return Err(());
        };
        if module_name != WASI_MODULE || !is_allowed_wasi_import(name) {
            return Err(());
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

fn add_wasi_functions(linker: &mut Linker<HostState>) -> Result<(), ()> {
    linker
        .func_wrap(WASI_MODULE, "fd_read", fd_read)
        .map_err(|_| ())?;
    linker
        .func_wrap(WASI_MODULE, "fd_write", fd_write)
        .map_err(|_| ())?;
    linker
        .func_wrap(WASI_MODULE, "fd_fdstat_get", fd_fdstat_get)
        .map_err(|_| ())?;
    linker
        .func_wrap(WASI_MODULE, "args_sizes_get", args_sizes_get)
        .map_err(|_| ())?;
    linker
        .func_wrap(WASI_MODULE, "args_get", args_get)
        .map_err(|_| ())?;
    linker
        .func_wrap(WASI_MODULE, "environ_sizes_get", environ_sizes_get)
        .map_err(|_| ())?;
    linker
        .func_wrap(WASI_MODULE, "environ_get", environ_get)
        .map_err(|_| ())?;
    linker
        .func_wrap(WASI_MODULE, "proc_exit", proc_exit)
        .map_err(|_| ())?;
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
    let arg_count = caller.data().args.len();
    let buf_size = caller
        .data()
        .args
        .iter()
        .map(|arg| arg.len().saturating_add(1))
        .sum::<usize>();
    let first = write_u32(&memory, &mut caller, argc, arg_count as u32);
    if first != ERR_SUCCESS {
        return first;
    }
    write_u32(&memory, &mut caller, argv_buf_size, buf_size as u32)
}

fn args_get(mut caller: Caller<'_, HostState>, argv: i32, argv_buf: i32) -> i32 {
    let Some(memory) = guest_memory(&caller) else {
        return ERR_FAULT;
    };
    let args = caller.data().args.clone();
    let mut buf_offset = ptr_to_usize(argv_buf);
    for (index, arg) in args.iter().enumerate() {
        let ptr = ptr_to_usize(argv).saturating_add(index.saturating_mul(4));
        let code = write_u32(&memory, &mut caller, ptr as i32, buf_offset as u32);
        if code != ERR_SUCCESS {
            return code;
        }
        if memory.write(&mut caller, buf_offset, arg).is_err() {
            return ERR_FAULT;
        }
        buf_offset = buf_offset.saturating_add(arg.len());
        if memory.write(&mut caller, buf_offset, &[0]).is_err() {
            return ERR_FAULT;
        }
        buf_offset = buf_offset.saturating_add(1);
    }
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
        let ptr = u32::from_le_bytes(buf[0..4].try_into().map_err(|_| ERR_FAULT)?) as usize;
        let len = u32::from_le_bytes(buf[4..8].try_into().map_err(|_| ERR_FAULT)?) as usize;
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

fn observation_hash(observation: &Observation) -> String {
    let mut hasher = blake3::Hasher::new();
    update_hash_field(&mut hasher, observation.program_hash.as_bytes());
    update_hash_field(&mut hasher, observation.seed_hex.as_bytes());
    update_hash_field(&mut hasher, observation.stdout_hash.as_bytes());
    update_hash_field(&mut hasher, observation.status.to_string().as_bytes());
    update_hash_field(&mut hasher, &observation.fuel_consumed.to_le_bytes());
    update_hash_field(&mut hasher, &observation.config.fuel.to_le_bytes());
    update_hash_field(
        &mut hasher,
        &(observation.config.memory_bytes as u64).to_le_bytes(),
    );
    update_hash_field(
        &mut hasher,
        observation
            .config
            .invoke
            .as_deref()
            .unwrap_or("")
            .as_bytes(),
    );
    hasher.finalize().to_hex().to_string()
}

fn update_hash_field(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn hash_bytes_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn seed_from_hex(seed_hex: &str) -> Option<Vec<u8>> {
    if seed_hex.is_empty() || !seed_hex.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(seed_hex.len() / 2);
    for pair in seed_hex.as_bytes().chunks_exact(2) {
        let high = hex_digit(pair[0])?;
        let low = hex_digit(pair[1])?;
        bytes.push((high << 4) | low);
    }
    Some(bytes)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
