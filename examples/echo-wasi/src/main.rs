use std::io::{self, Read, Write};

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().lock().read_to_end(&mut input)?;
    let mut output = io::stdout().lock();
    output.write_all(&input)?;
    output.flush()
}
