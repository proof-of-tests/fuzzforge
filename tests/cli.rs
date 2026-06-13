use std::{
    fs,
    process::Command,
    sync::{
        Mutex,
        atomic::{AtomicU16, Ordering},
        mpsc,
    },
    thread,
};

use tempfile::tempdir;

static HTTP_TEST_LOCK: Mutex<()> = Mutex::new(());
static NEXT_TEST_PORT: AtomicU16 = AtomicU16::new(18080);

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

fn associated_echo_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"
        (module
          (import "wasi_snapshot_preview1" "fd_read"
            (func $fd_read (param i32 i32 i32 i32) (result i32)))
          (import "wasi_snapshot_preview1" "fd_write"
            (func $fd_write (param i32 i32 i32 i32) (result i32)))
          (import "wasi_snapshot_preview1" "args_sizes_get"
            (func $args_sizes_get (param i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 128) "{\22github_repository\22:\22owner/repo\22,\22component_name\22:\22api\22,\22version\22:\221.2.3\22}")
          (func (export "_start")
            (drop (call $args_sizes_get (i32.const 92) (i32.const 96)))
            (if (i32.gt_u (i32.load (i32.const 92)) (i32.const 1))
              (then
                (i32.store (i32.const 0) (i32.const 128))
                (i32.store (i32.const 4) (i32.const 75))
                (drop (call $fd_write
                  (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 100))))
              (else
                (i32.store (i32.const 0) (i32.const 16))
                (i32.store (i32.const 4) (i32.const 64))
                (drop (call $fd_read
                  (i32.const 0) (i32.const 0) (i32.const 1) (i32.const 84)))
                (i32.store (i32.const 8) (i32.const 16))
                (i32.store (i32.const 12) (i32.load (i32.const 84)))
                (drop (call $fd_write
                  (i32.const 1) (i32.const 8) (i32.const 1) (i32.const 88)))))))
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
    assert_eq!(stderr(&run), "proven_before=0.000\nproven_added=1.008\n");

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
    assert!(!stats_stdout.contains("runs="));
    assert!(stats_stdout.contains("stored_observations=1"));
    assert!(stats_stdout.contains("estimated_observations=1.008"));

    let list = Command::new(env!("CARGO_BIN_EXE_fuzzforge"))
        .args(["list", "--store", store_path.to_str().unwrap()])
        .output()
        .expect("list command");
    assert!(list.status.success(), "stderr: {}", stderr(&list));
    let list_stdout = stdout(&list);
    assert!(!list_stdout.contains("runs="));
    assert!(list_stdout.contains("estimate=1.008"));
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
fn duplicate_runs_do_not_increase_hll_progress() {
    let temp = tempdir().expect("tempdir");
    let wasm_path = temp.path().join("echo.wasm");
    let store_path = temp.path().join("store");
    fs::write(&wasm_path, echo_wasm()).expect("write wasm");

    for expected_stderr in [
        "proven_before=0.000\nproven_added=1.008\n",
        "proven_before=1.008\nproven_added=0.000\n",
    ] {
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
        assert_eq!(stderr(&output), expected_stderr);
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
    assert!(stdout(&stats).contains("stored_observations=2"));
    assert!(stdout(&stats).contains("estimated_observations=1.008"));
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

    let run_stderr = stderr(&run);
    let lines: Vec<&str> = run_stderr.lines().collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0], "proven_before=0.000");
    assert!(lines[1].starts_with("proven_added="));
    assert!(lines[2].starts_with("proven_added="));

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
    assert!(!stats_stdout.contains("runs="));
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
fn run_progress_ignores_stored_run_counter() {
    let temp = tempdir().expect("tempdir");
    let wasm_path = temp.path().join("echo.wasm");
    let store_path = temp.path().join("store");
    fs::write(&wasm_path, echo_wasm()).expect("write wasm");

    let first = Command::new(env!("CARGO_BIN_EXE_fuzzforge"))
        .args([
            "run",
            wasm_path.to_str().unwrap(),
            "--seed",
            "73616d6520696e707574",
            "--store",
            store_path.to_str().unwrap(),
        ])
        .output()
        .expect("run command");
    assert!(first.status.success(), "stderr: {}", stderr(&first));

    let hll_dir = store_path.join("hll");
    let record_path = fs::read_dir(&hll_dir)
        .expect("read hll dir")
        .next()
        .expect("record entry")
        .expect("record entry")
        .path();
    let mut record: serde_json::Value =
        serde_json::from_slice(&fs::read(&record_path).expect("read record")).expect("json");
    record["run_count"] = serde_json::json!(999);
    fs::write(
        &record_path,
        serde_json::to_vec_pretty(&record).expect("serialize record"),
    )
    .expect("write record");

    let second = Command::new(env!("CARGO_BIN_EXE_fuzzforge"))
        .args([
            "run",
            wasm_path.to_str().unwrap(),
            "--seed",
            "73616d6520696e707574",
            "--store",
            store_path.to_str().unwrap(),
        ])
        .output()
        .expect("run command");
    assert!(second.status.success(), "stderr: {}", stderr(&second));
    assert_eq!(stderr(&second), "proven_before=1.008\nproven_added=0.000\n");
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

#[test]
fn save_fuel_interval_must_be_nonzero() {
    let temp = tempdir().expect("tempdir");
    let wasm_path = temp.path().join("echo.wasm");
    fs::write(&wasm_path, echo_wasm()).expect("write wasm");

    let run = Command::new(env!("CARGO_BIN_EXE_fuzzforge"))
        .args(["run", wasm_path.to_str().unwrap(), "--save-fuel-interval=0"])
        .output()
        .expect("run command");
    assert!(!run.status.success());
    assert!(stderr(&run).contains("--save-fuel-interval must be greater than zero"));
}

#[test]
fn submit_uploads_wasm_and_proof() {
    let _guard = HTTP_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp = tempdir().expect("tempdir");
    let wasm_path = temp.path().join("echo.wasm");
    let store_path = temp.path().join("store");
    let wasm = echo_wasm();
    fs::write(&wasm_path, &wasm).expect("write wasm");

    let run = Command::new(env!("CARGO_BIN_EXE_fuzzforge"))
        .args([
            "run",
            wasm_path.to_str().unwrap(),
            "--seed",
            "7375626d6974",
            "--store",
            store_path.to_str().unwrap(),
        ])
        .output()
        .expect("run command");
    assert!(run.status.success(), "stderr: {}", stderr(&run));

    let (server, api_url) = test_server();
    let expected_hash = blake3::hash(&wasm).to_hex().to_string();
    let (tx, rx) = mpsc::channel();
    let server_thread = thread::spawn(move || {
        for _ in 0..2 {
            let mut request = server.recv().expect("request");
            let mut body = Vec::new();
            std::io::Read::read_to_end(request.as_reader(), &mut body).expect("body");
            tx.send((
                request.method().as_str().to_owned(),
                request.url().to_owned(),
                request
                    .headers()
                    .iter()
                    .find(|header| header.field.equiv("authorization"))
                    .map(|header| header.value.as_str().to_owned()),
                body,
            ))
            .expect("send request");
            request
                .respond(
                    tiny_http::Response::from_string("{}").with_header(
                        tiny_http::Header::from_bytes(
                            b"content-type".as_slice(),
                            b"application/json".as_slice(),
                        )
                        .unwrap(),
                    ),
                )
                .expect("respond");
        }
    });

    let submit = Command::new(env!("CARGO_BIN_EXE_fuzzforge"))
        .args([
            "submit",
            wasm_path.to_str().unwrap(),
            "--store",
            store_path.to_str().unwrap(),
            "--api-url",
            &api_url,
        ])
        .output()
        .expect("submit command");
    assert!(submit.status.success(), "stderr: {}", stderr(&submit));
    assert!(stdout(&submit).contains(&format!("submitted_proof={expected_hash}")));

    let first = rx.recv().expect("first request");
    let second = rx.recv().expect("second request");
    server_thread.join().expect("server thread");

    assert_eq!(first.0, "PUT");
    assert_eq!(first.1, format!("/api/programs/{expected_hash}/wasm"));
    assert_eq!(first.2, None);
    assert_eq!(first.3, wasm);

    assert_eq!(second.0, "POST");
    assert_eq!(second.1, format!("/api/programs/{expected_hash}/proof"));
    assert_eq!(second.2, None);
    let proof: serde_json::Value = serde_json::from_slice(&second.3).expect("proof json");
    assert_eq!(proof["program_hash"], expected_hash);
    assert_eq!(proof["observations"].as_array().unwrap().len(), 1);
}

#[test]
fn associated_submit_sends_stored_github_token() {
    let _guard = HTTP_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp = tempdir().expect("tempdir");
    let wasm_path = temp.path().join("echo.wasm");
    let store_path = temp.path().join("store");
    let config_path = temp.path().join("config");
    let wasm = associated_echo_wasm();
    fs::write(&wasm_path, &wasm).expect("write wasm");
    let token_dir = config_path.join("fuzzforge");
    fs::create_dir_all(&token_dir).expect("create token dir");
    fs::write(
        token_dir.join("github.json"),
        br#"{"access_token":"test-token","expires_at":4102444800}"#,
    )
    .expect("write token");

    let run = Command::new(env!("CARGO_BIN_EXE_fuzzforge"))
        .args([
            "run",
            wasm_path.to_str().unwrap(),
            "--seed",
            "7375626d6974",
            "--store",
            store_path.to_str().unwrap(),
        ])
        .output()
        .expect("run command");
    assert!(run.status.success(), "stderr: {}", stderr(&run));

    let (server, api_url) = test_server();
    let expected_hash = blake3::hash(&wasm).to_hex().to_string();
    let (tx, rx) = mpsc::channel();
    let server_thread = thread::spawn(move || {
        for _ in 0..2 {
            let mut request = server.recv().expect("request");
            let mut body = Vec::new();
            std::io::Read::read_to_end(request.as_reader(), &mut body).expect("body");
            tx.send((
                request.method().as_str().to_owned(),
                request.url().to_owned(),
                request
                    .headers()
                    .iter()
                    .find(|header| header.field.equiv("authorization"))
                    .map(|header| header.value.as_str().to_owned()),
                body,
            ))
            .expect("send request");
            request
                .respond(tiny_http::Response::from_string("{}"))
                .expect("respond");
        }
    });

    let submit = Command::new(env!("CARGO_BIN_EXE_fuzzforge"))
        .env("XDG_CONFIG_HOME", &config_path)
        .args([
            "submit",
            wasm_path.to_str().unwrap(),
            "--store",
            store_path.to_str().unwrap(),
            "--api-url",
            &api_url,
        ])
        .output()
        .expect("submit command");
    assert!(submit.status.success(), "stderr: {}", stderr(&submit));

    let first = rx.recv().expect("first request");
    let second = rx.recv().expect("second request");
    server_thread.join().expect("server thread");

    assert_eq!(first.0, "PUT");
    assert_eq!(first.1, format!("/api/programs/{expected_hash}/wasm"));
    assert_eq!(first.2, Some("Bearer test-token".to_owned()));
    assert_eq!(second.0, "POST");
    assert_eq!(second.2, None);
}

#[test]
fn associated_submit_without_token_fails_before_upload() {
    let temp = tempdir().expect("tempdir");
    let wasm_path = temp.path().join("echo.wasm");
    let store_path = temp.path().join("store");
    let config_path = temp.path().join("config");
    fs::write(&wasm_path, associated_echo_wasm()).expect("write wasm");

    let run = Command::new(env!("CARGO_BIN_EXE_fuzzforge"))
        .args([
            "run",
            wasm_path.to_str().unwrap(),
            "--seed",
            "7375626d6974",
            "--store",
            store_path.to_str().unwrap(),
        ])
        .output()
        .expect("run command");
    assert!(run.status.success(), "stderr: {}", stderr(&run));

    let submit = Command::new(env!("CARGO_BIN_EXE_fuzzforge"))
        .env("XDG_CONFIG_HOME", &config_path)
        .args([
            "submit",
            wasm_path.to_str().unwrap(),
            "--store",
            store_path.to_str().unwrap(),
            "--api-url",
            "http://127.0.0.1:9",
        ])
        .output()
        .expect("submit command");
    assert!(!submit.status.success());
    assert!(stderr(&submit).contains("fuzzforge auth login"));
}

#[test]
fn corpus_downloads_associated_programs_runs_and_submits() {
    let _guard = HTTP_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp = tempdir().expect("tempdir");
    let store_path = temp.path().join("store");
    let config_path = temp.path().join("config");
    let wasm = associated_echo_wasm();
    let expected_hash = blake3::hash(&wasm).to_hex().to_string();
    let token_dir = config_path.join("fuzzforge");
    fs::create_dir_all(&token_dir).expect("create token dir");
    fs::write(
        token_dir.join("github.json"),
        br#"{"access_token":"test-token","expires_at":4102444800}"#,
    )
    .expect("write token");

    let (server, api_url) = test_server();
    let (tx, rx) = mpsc::channel();
    let server_thread = thread::spawn({
        let expected_hash = expected_hash.clone();
        let wasm = wasm.clone();
        move || {
            for _ in 0..4 {
                let mut request = server.recv().expect("request");
                let mut body = Vec::new();
                std::io::Read::read_to_end(request.as_reader(), &mut body).expect("body");
                let method = request.method().as_str().to_owned();
                let url = request.url().to_owned();
                let authorization = request
                    .headers()
                    .iter()
                    .find(|header| header.field.equiv("authorization"))
                    .map(|header| header.value.as_str().to_owned());
                tx.send((method.clone(), url.clone(), authorization, body))
                    .expect("send request");

                let response = match (method.as_str(), url.as_str()) {
                    ("GET", "/api/programs?associated=true&limit=100") => {
                        tiny_http::Response::from_string(format!(
                            r#"{{"programs":[{{"program_hash":"{expected_hash}","github_repository":"owner/repo"}}],"next_cursor":null}}"#
                        ))
                        .with_header(
                            tiny_http::Header::from_bytes(
                                b"content-type".as_slice(),
                                b"application/json".as_slice(),
                            )
                            .unwrap(),
                        )
                    }
                    ("GET", path) if path == format!("/api/programs/{expected_hash}/wasm") => {
                        tiny_http::Response::from_data(wasm.clone()).with_header(
                            tiny_http::Header::from_bytes(
                                b"content-type".as_slice(),
                                b"application/wasm".as_slice(),
                            )
                            .unwrap(),
                        )
                    }
                    _ => tiny_http::Response::from_string("{}").with_header(
                        tiny_http::Header::from_bytes(
                            b"content-type".as_slice(),
                            b"application/json".as_slice(),
                        )
                        .unwrap(),
                    ),
                };
                request.respond(response).expect("respond");
            }
        }
    });

    let corpus = Command::new(env!("CARGO_BIN_EXE_fuzzforge"))
        .env("XDG_CONFIG_HOME", &config_path)
        .args([
            "corpus",
            "--api-url",
            &api_url,
            "--store",
            store_path.to_str().unwrap(),
            "--fuel-budget=1",
            "--cycles=1",
        ])
        .output()
        .expect("corpus command");
    assert!(corpus.status.success(), "stderr: {}", stderr(&corpus));
    assert!(stdout(&corpus).contains(&format!("submitted_proof={expected_hash}")));

    let requests: Vec<_> = (0..4).map(|_| rx.recv().expect("request")).collect();
    server_thread.join().expect("server thread");
    assert_eq!(requests[0].0, "GET");
    assert_eq!(requests[0].1, "/api/programs?associated=true&limit=100");
    assert_eq!(requests[1].0, "GET");
    assert_eq!(requests[1].1, format!("/api/programs/{expected_hash}/wasm"));
    assert_eq!(requests[2].0, "PUT");
    assert_eq!(requests[2].1, format!("/api/programs/{expected_hash}/wasm"));
    assert_eq!(requests[2].2, Some("Bearer test-token".to_owned()));
    assert_eq!(requests[2].3, wasm);
    assert_eq!(requests[3].0, "POST");
    assert_eq!(
        requests[3].1,
        format!("/api/programs/{expected_hash}/proof")
    );
    let proof: serde_json::Value = serde_json::from_slice(&requests[3].3).expect("proof json");
    assert_eq!(proof["program_hash"], expected_hash);
    assert_eq!(proof["observations"].as_array().unwrap().len(), 1);
}

fn test_server() -> (tiny_http::Server, String) {
    for _ in 0..100 {
        let port = NEXT_TEST_PORT.fetch_add(1, Ordering::Relaxed);
        if let Ok(server) = tiny_http::Server::http(format!("[::1]:{port}")) {
            return (server, format!("http://[::1]:{port}"));
        }
    }
    panic!("failed to bind test HTTP server")
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
