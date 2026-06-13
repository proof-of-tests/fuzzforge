use std::{
    env,
    io::{self, Read, Write},
};

fn main() -> io::Result<()> {
    if env::args().any(|arg| arg == "--metadata") {
        println!(
            r#"{{"github_repository":"proof-of-tests/fuzzforge","component_name":"echo-wasi","version":"0.1.0"}}"#
        );
        return Ok(());
    }

    if env::args().any(|arg| arg == "--repository") {
        println!("proof-of-tests/fuzzforge");
        return Ok(());
    }

    let mut input = Vec::new();
    io::stdin().lock().read_to_end(&mut input)?;
    let mut output = io::stdout().lock();
    output.write_all(&input)?;
    output.flush()
}
