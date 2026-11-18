use omni_core::{DataPayload, ExecutionContext, Operation};
use omni_filesystems::EmbeddedSqlOp;
use omni_media::MediaTranscodeOp;
use omni_network::DnsPowerSuiteOp;
use omni_security::{
    redact_secrets, safe_join, safe_join_no_symlinks, sanitize_error_message,
    validate_network_target, ResourceLimits,
};
use std::path::Path;

#[test]
fn test_decompression_bomb_limits() {
    let limits = ResourceLimits::default();

    // 1. Ratio violation: 10 bytes -> 2000 bytes (ratio 200:1, exceeds 100:1 limit)
    let ratio_check = limits.check_decompression(10, 2000);
    assert!(ratio_check.is_err());

    // 2. Integer-truncation edge case: 1009 / 10 = 100.9x MUST be rejected!
    assert!(limits.check_decompression(10, 1009).is_err());

    // 3. Zero-length compressed stream claiming non-zero output MUST be rejected
    assert!(limits.check_decompression(0, 10).is_err());

    // 4. Absolute size violation: exceeds 500MB max
    assert!(limits.check_decompression(10_000_000, 600 * 1024 * 1024).is_err());

    // 5. Normal safe decompression: 1000 bytes -> 5000 bytes (5:1 ratio)
    assert!(limits.check_decompression(1000, 5000).is_ok());
}

#[test]
fn test_network_target_sandboxing() {
    assert!(validate_network_target("127.0.0.1", false).is_ok());
    assert!(validate_network_target("::1", false).is_ok());
    assert!(validate_network_target("localhost", false).is_ok());
    assert!(validate_network_target("192.168.1.1", false).is_ok());
    assert!(validate_network_target("10.0.0.1", false).is_ok());
    assert!(validate_network_target("172.16.0.1", false).is_ok());

    assert!(validate_network_target("8.8.8.8", false).is_err());
    assert!(validate_network_target("1.1.1.1", false).is_err());
    assert!(validate_network_target("evil.example.com", false).is_err());
    assert!(validate_network_target("8.8.8.8", true).is_ok());
}

#[test]
fn test_secret_and_path_redaction_engine() {
    let log_with_secret = "Error in C:\\Users\\admin\\keys with AKIAIOSFODNN7EXAMPLE and ghp_1234567890abcdef1234567890 and Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M";
    let redacted = redact_secrets(log_with_secret);
    assert!(!redacted.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(!redacted.contains("ghp_1234567890"));
    assert!(!redacted.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));

    let sanitized = sanitize_error_message(log_with_secret);
    assert!(!sanitized.contains("admin"));
    assert!(sanitized.contains("<USER_HOME>"));
}

#[test]
fn test_filesystem_traversal_and_symlink_protection() {
    let root = std::env::temp_dir().join(format!("omni_sec_fs_{}", std::process::id()));
    let sandbox = root.join("sandbox");
    let outside = root.join("outside");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&sandbox).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("flag.txt"), b"secret").unwrap();

    assert!(safe_join(&sandbox, Path::new("../outside/flag.txt")).is_err());
    assert!(safe_join(&sandbox, Path::new("ok\0bad.txt")).is_err());

    let link = sandbox.join("sym_out");
    #[cfg(unix)]
    let ok = std::os::unix::fs::symlink(&outside, &link).is_ok();
    #[cfg(windows)]
    let ok = std::os::windows::fs::symlink_dir(&outside, &link).is_ok();
    if ok {
        assert!(safe_join(&sandbox, Path::new("sym_out/flag.txt")).is_err());
        assert!(safe_join_no_symlinks(&sandbox, Path::new("sym_out/flag.txt")).is_err());
    }

    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn test_sql_readonly_and_dns_scope_and_ffmpeg_injection_guards() {
    let ctx = ExecutionContext::new("sec_ops");

    // 1. SQL ATTACH DATABASE must be rejected
    let sql_op = EmbeddedSqlOp;
    let res = sql_op
        .execute(
            DataPayload::text("id,name\n1,alice"),
            serde_json::json!({ "query": "ATTACH DATABASE '/tmp/pwn.db' AS pwn" }),
            &ctx,
        )
        .await;
    assert!(res.is_err());

    // 2. DNS external server query without allow_external=true must be rejected
    let dns_op = DnsPowerSuiteOp;
    let res = dns_op
        .execute(
            DataPayload::text("example.com"),
            serde_json::json!({ "action": "query", "server": "1.1.1.1:53" }),
            &ctx,
        )
        .await;
    assert!(res.is_err());

    // 3. FFmpeg argument/codec injection must be rejected before spawning anything
    let media_op = MediaTranscodeOp;
    let res = media_op
        .execute(
            DataPayload::text(""),
            serde_json::json!({ "mode": "plan", "vcodec": "libx264; rm -rf /" }),
            &ctx,
        )
        .await;
    assert!(res.is_err());
}
