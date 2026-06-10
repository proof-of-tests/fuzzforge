use std::{fs, process::Command};

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
    let store_path = temp.path().join("store");
    fs::write(&wasm_path, echo_wasm()).expect("write wasm");

    let run = Command::new(env!("CARGO_BIN_EXE_fuzzforge"))
        .args([
            "run",
            wasm_path.to_str().unwrap(),
            "--seed",
            "68656c6c6f20636c69",
            "--store",
            store_path.to_str().unwrap(),
        ])
        .output()
        .expect("run command");
    assert!(run.status.success(), "stderr: {}", stderr(&run));
    assert!(run.stdout.is_empty());
    assert_eq!(stderr(&run), "proven_before=0\nproven_added=1\n");

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
    assert!(stats_stdout.contains("stored_observations=1"));

    let list = Command::new(env!("CARGO_BIN_EXE_fuzzforge"))
        .args(["list", "--store", store_path.to_str().unwrap()])
        .output()
        .expect("list command");
    assert!(list.status.success(), "stderr: {}", stderr(&list));
    let list_stdout = stdout(&list);
    assert!(list_stdout.contains("runs=1"));
    assert!(list_stdout.contains("precision=6"));
    assert!(list_stdout.contains("buckets=64"));

    let verify = Command::new(env!("CARGO_BIN_EXE_fuzzforge"))
        .args([
            "verify",
            wasm_path.to_str().unwrap(),
            "--store",
            store_path.to_str().unwrap(),
        ])
        .output()
        .expect("verify command");
    assert!(verify.status.success(), "stderr: {}", stderr(&verify));
    assert!(stdout(&verify).contains("verification=ok"));
    assert!(stdout(&verify).contains("checked_observations=1"));
}

#[test]
fn repeated_runs_increment_run_count_without_stdout_forwarding() {
    let temp = tempdir().expect("tempdir");
    let wasm_path = temp.path().join("echo.wasm");
    let store_path = temp.path().join("store");
    fs::write(&wasm_path, echo_wasm()).expect("write wasm");

    for expected_before in [0, 1] {
        let output = Command::new(env!("CARGO_BIN_EXE_fuzzforge"))
            .args([
                "run",
                wasm_path.to_str().unwrap(),
                "--store",
                store_path.to_str().unwrap(),
                "--seed",
                "73616d6520696e707574",
            ])
            .output()
            .expect("run command");
        assert!(output.status.success(), "stderr: {}", stderr(&output));
        assert!(output.stdout.is_empty());
        assert_eq!(
            stderr(&output),
            format!("proven_before={expected_before}\nproven_added=1\n")
        );
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

#[test]
fn count_runs_multiple_generated_seeds_and_verifies() {
    let temp = tempdir().expect("tempdir");
    let wasm_path = temp.path().join("echo.wasm");
    let store_path = temp.path().join("store");
    fs::write(&wasm_path, echo_wasm()).expect("write wasm");

    let run = Command::new(env!("CARGO_BIN_EXE_fuzzforge"))
        .args([
            "run",
            wasm_path.to_str().unwrap(),
            "--store",
            store_path.to_str().unwrap(),
            "--count=2",
        ])
        .output()
        .expect("run command");
    assert!(run.status.success(), "stderr: {}", stderr(&run));
    assert!(run.stdout.is_empty());

    assert_eq!(stderr(&run), "proven_before=0\nproven_added=2\n");

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
    assert!(stats_stdout.contains("runs=2"));
    assert!(stats_stdout.contains("stored_observations=2"));

    let verify = Command::new(env!("CARGO_BIN_EXE_fuzzforge"))
        .args([
            "verify",
            wasm_path.to_str().unwrap(),
            "--store",
            store_path.to_str().unwrap(),
        ])
        .output()
        .expect("verify command");
    assert!(verify.status.success(), "stderr: {}", stderr(&verify));
    assert!(stdout(&verify).contains("checked_observations=2"));
    assert!(stdout(&verify).contains("verification=ok"));
}

#[test]
fn stdout_forwarding_flags_are_not_supported() {
    let temp = tempdir().expect("tempdir");
    let wasm_path = temp.path().join("echo.wasm");
    fs::write(&wasm_path, echo_wasm()).expect("write wasm");

    for flag in ["--stdout", "--no-stdout"] {
        let run = Command::new(env!("CARGO_BIN_EXE_fuzzforge"))
            .args(["run", wasm_path.to_str().unwrap(), flag])
            .output()
            .expect("run command");
        assert!(!run.status.success());
        assert!(stderr(&run).contains("unexpected argument"));
    }
}

#[test]
fn count_rejects_explicit_seed_for_multiple_runs() {
    let temp = tempdir().expect("tempdir");
    let wasm_path = temp.path().join("echo.wasm");
    fs::write(&wasm_path, echo_wasm()).expect("write wasm");

    let run = Command::new(env!("CARGO_BIN_EXE_fuzzforge"))
        .args([
            "run",
            wasm_path.to_str().unwrap(),
            "--seed",
            "00",
            "--count=2",
        ])
        .output()
        .expect("run command");
    assert!(!run.status.success());
    assert!(stderr(&run).contains("--seed can only be used when --count=1"));
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
