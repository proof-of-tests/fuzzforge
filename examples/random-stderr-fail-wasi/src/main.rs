use std::{
    env,
    io::{self, Read},
};

const FAILURE_RATE: u64 = 10_000_000;
const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

fn main() -> io::Result<()> {
    if env::args().any(|arg| arg == "--metadata") {
        println!(
            r#"{{"github_repository":"proof-of-tests/fuzzforge","component_name":"random-stderr-fail-wasi","version":"0.1.0"}}"#
        );
        return Ok(());
    }

    let mut input = Vec::new();
    io::stdin().lock().read_to_end(&mut input)?;
    let hash = stable_hash(&input);
    if hash % FAILURE_RATE == 0 {
        eprintln!("random-stderr-fail-wasi failure hash={hash:016x}");
    }
    Ok(())
}

fn stable_hash(input: &[u8]) -> u64 {
    input.iter().fold(FNV_OFFSET_BASIS, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(FNV_PRIME)
    })
}
