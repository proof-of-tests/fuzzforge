use std::{
    fs,
    process::{Command, Stdio},
};

use tempfile::tempdir;

fn echo_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"
        (module
          (import "wasi_snapshot_preview1" "fd_read"
            (func $fd_read (param i32 i32 i32 i32) (result i32)))
          (import "wasi_snapshot_preview1" "fd_write"
            (func $fd_write (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (func (export "_start")
            (i32.store (i32.const 0) (i32.const 16))
            (i32.store (i32.const 4) (i32.const 64))
            (drop (call $fd_read
              (i32.const 0) (i32.const 0) (i32.const 1) (i32.const 84)))
            (i32.store (i32.const 8) (i32.const 16))
            (i32.store (i32.const 12) (i32.load (i32.const 84)))
            (drop (call $fd_write
              (i32.const 1) (i32.const 8) (i32.const 1) (i32.const 88)))))
        "#,
    )
    .expect("valid wat")
}

#[test]
fn run_stats_and_list_persist_hll() {
    let temp = tempdir().expect("tempdir");
    let wasm_path = temp.path().join("echo.wasm");
    let input_path = temp.path().join("input.bin");
    let store_path = temp.path().join("store");
    fs::write(&wasm_path, echo_wasm()).expect("write wasm");
    fs::write(&input_path, b"hello cli").expect("write input");

    let run = Command::new(env!("CARGO_BIN_EXE_fuzzforge"))
        .args([
            "run",
            wasm_path.to_str().unwrap(),
            "--stdin-file",
            input_path.to_str().unwrap(),
            "--store",
            store_path.to_str().unwrap(),
        ])
        .output()
        .expect("run command");
    assert!(run.status.success(), "stderr: {}", stderr(&run));
    assert_eq!(run.stdout, b"hello cli");
    assert!(stderr(&run).contains("hll_precision=6"));
    assert!(stderr(&run).contains("hll_buckets=64"));

    let stats = Command::new(env!("CARGO_BIN_EXE_fuzzforge"))
        .args([
            "stats",
            wasm_path.to_str().unwrap(),
            "--store",
            store_path.to_str().unwrap(),
        ])
        .output()
        .expect("stats command");
    assert!(stats.status.success(), "stderr: {}", stderr(&stats));
    let stats_stdout = stdout(&stats);
    assert!(stats_stdout.contains("precision=6"));
    assert!(stats_stdout.contains("buckets=64"));
    assert!(stats_stdout.contains("runs=1"));

    let list = Command::new(env!("CARGO_BIN_EXE_fuzzforge"))
        .args(["list", "--store", store_path.to_str().unwrap()])
        .output()
        .expect("list command");
    assert!(list.status.success(), "stderr: {}", stderr(&list));
    let list_stdout = stdout(&list);
    assert!(list_stdout.contains("runs=1"));
    assert!(list_stdout.contains("precision=6"));
    assert!(list_stdout.contains("buckets=64"));
}

#[test]
fn repeated_runs_increment_run_count_without_stdout_forwarding() {
    let temp = tempdir().expect("tempdir");
    let wasm_path = temp.path().join("echo.wasm");
    let store_path = temp.path().join("store");
    fs::write(&wasm_path, echo_wasm()).expect("write wasm");

    for _ in 0..2 {
        let mut child = Command::new(env!("CARGO_BIN_EXE_fuzzforge"))
            .args([
                "run",
                wasm_path.to_str().unwrap(),
                "--store",
                store_path.to_str().unwrap(),
                "--no-stdout",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn run command");
        std::io::Write::write_all(child.stdin.as_mut().unwrap(), b"same input")
            .expect("write stdin");
        let output = child.wait_with_output().expect("wait for run");
        assert!(output.status.success(), "stderr: {}", stderr(&output));
        assert!(output.stdout.is_empty());
    }

    let stats = Command::new(env!("CARGO_BIN_EXE_fuzzforge"))
        .args([
            "stats",
            wasm_path.to_str().unwrap(),
            "--store",
            store_path.to_str().unwrap(),
        ])
        .output()
        .expect("stats command");
    assert!(stats.status.success(), "stderr: {}", stderr(&stats));
    assert!(stdout(&stats).contains("runs=2"));
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
