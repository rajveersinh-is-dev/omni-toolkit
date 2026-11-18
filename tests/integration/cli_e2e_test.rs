use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn omni_bin() -> PathBuf {
    // Ensure binary exists (built by cargo test --workspace or cargo build -p omni)
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop(); // workspace root
    path.push("target");
    path.push("debug");
    if cfg!(windows) {
        path.push("omni.exe");
    } else {
        path.push("omni");
    }
    if !path.is_file() {
        let status = Command::new("cargo")
            .args(["build", "-p", "omni"])
            .status()
            .expect("failed to build omni CLI binary");
        assert!(status.success(), "cargo build -p omni failed");
    }
    path
}

#[test]
fn test_cli_category_filtering_actually_filters() {
    let bin = omni_bin();

    // 1. Filter by Encoders category -> ALL returned items must be Encoders
    let out = Command::new(&bin)
        .args(["--json", "list", "--category", "Encoders"])
        .output()
        .expect("failed to execute omni list");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let items: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout).unwrap();
    assert!(!items.is_empty());
    for item in &items {
        assert_eq!(
            item["category"], "Encoders",
            "Non-encoder leaked into filtered list: {}",
            item
        );
    }

    // 2. Combined category + query filter
    let out2 = Command::new(&bin)
        .args([
            "--json",
            "list",
            "--category",
            "Encoders",
            "--query",
            "base64",
        ])
        .output()
        .unwrap();
    assert!(out2.status.success());
    let items2: Vec<serde_json::Value> = serde_json::from_slice(&out2.stdout).unwrap();
    assert!(!items2.is_empty() && items2.len() <= 3);
    assert!(items2
        .iter()
        .all(|i| i["id"].as_str().unwrap().contains("base64")));

    // 3. Invalid category must fail with non-zero exit code and stderr message
    let bad = Command::new(&bin)
        .args(["list", "--category", "TotallyFakeCategory"])
        .output()
        .unwrap();
    assert!(!bad.status.success());
    assert!(String::from_utf8_lossy(&bad.stderr).contains("Unknown category"));
}

#[test]
fn test_cli_inventory_and_pqc_and_remote_serve_guard() {
    let bin = omni_bin();

    // 1. Machine-readable inventory
    let inv_out = Command::new(&bin)
        .args(["--json", "inventory"])
        .output()
        .unwrap();
    assert!(inv_out.status.success());
    let inv: serde_json::Value = serde_json::from_slice(&inv_out.stdout).unwrap();
    assert!(inv["total_operations"].as_u64().unwrap() >= 100);

    // 2. Real FIPS 203 ML-KEM roundtrip through CLI
    let mut child = Command::new(&bin)
        .args([
            "run",
            "crypto.pqc.ml_kem",
            "--config",
            r#"{"action":"roundtrip"}"#,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdin.take());
    let pqc_out = child.wait_with_output().unwrap();
    assert!(
        pqc_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&pqc_out.stderr)
    );
    let pqc_json: serde_json::Value = serde_json::from_slice(&pqc_out.stdout).unwrap();
    assert_eq!(pqc_json["shared_secrets_match"], true);

    // 3. Falcon must honestly fail as unsupported
    let mut falcon_child = Command::new(&bin)
        .args(["run", "crypto.pqc.falcon"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(falcon_child.stdin.take());
    let falcon_out = falcon_child.wait_with_output().unwrap();
    assert!(!falcon_out.status.success());
    assert!(String::from_utf8_lossy(&falcon_out.stderr).contains("unsupported"));

    // 4. Remote non-loopback serve without --auth-token must be rejected
    let remote = Command::new(&bin)
        .args(["serve", "--host", "0.0.0.0", "--port", "9999"])
        .output()
        .unwrap();
    assert!(!remote.status.success());
    assert!(String::from_utf8_lossy(&remote.stderr).contains("Security Error"));
}

#[test]
fn test_cli_stdin_pipe_and_pipeline_run() {
    let bin = omni_bin();

    // UNIX stdin -> encode base64
    let mut child = Command::new(&bin)
        .args(["encode", "base64"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"hello omni")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout), "aGVsbG8gb21uaQ==");

    // Pipeline validate & run with JSON report
    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    let pipe_file = root
        .join("docs")
        .join("pipeline-examples")
        .join("hash_and_hex.json");

    let val_out = Command::new(&bin)
        .args(["pipeline", "validate", pipe_file.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(val_out.status.success());

    let mut p_child = Command::new(&bin)
        .args(["--json", "pipeline", "run", pipe_file.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    p_child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"pipeline payload")
        .unwrap();
    let p_out = p_child.wait_with_output().unwrap();
    assert!(p_out.status.success());
    let report: serde_json::Value = serde_json::from_slice(&p_out.stdout).unwrap();
    assert_eq!(report["status"], "completed");
    assert_eq!(report["nodes"].as_array().unwrap().len(), 2);
}
