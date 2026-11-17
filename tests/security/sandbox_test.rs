use omni_security::{redact_secrets, validate_network_target, ResourceLimits};

#[test]
fn test_decompression_bomb_limits() {
    let limits = ResourceLimits::default();

    // 1. Ratio violation: 10 bytes -> 2000 bytes (ratio 200:1, exceeds 100:1 limit)
    let ratio_check = limits.check_decompression(10, 2000);
    assert!(ratio_check.is_err());
    let err = ratio_check.unwrap_err().to_string();
    assert!(err.contains("ratio") || err.contains("100"));

    // 2. Absolute size violation: exceeds 500MB max
    let size_check = limits.check_decompression(10_000_000, 600 * 1024 * 1024);
    assert!(size_check.is_err());

    // 3. Normal safe decompression: 1000 bytes -> 5000 bytes (5:1 ratio)
    assert!(limits.check_decompression(1000, 5000).is_ok());
}

#[test]
fn test_network_target_sandboxing() {
    // Loopback targets are permitted
    assert!(validate_network_target("127.0.0.1", false).is_ok());
    assert!(validate_network_target("::1", false).is_ok());
    assert!(validate_network_target("localhost", false).is_ok());

    // RFC 1918 private subnets are permitted for lab testing
    assert!(validate_network_target("192.168.1.1", false).is_ok());
    assert!(validate_network_target("10.0.0.1", false).is_ok());
    assert!(validate_network_target("172.16.0.1", false).is_ok());

    // Public internet IP ranges must fail when allow_external is false
    assert!(validate_network_target("8.8.8.8", false).is_err());
    assert!(validate_network_target("1.1.1.1", false).is_err());
    assert!(validate_network_target("evil.example.com", false).is_err());

    // Explicitly allowed external scope
    assert!(validate_network_target("8.8.8.8", true).is_ok());
}

#[test]
fn test_secret_redaction_engine() {
    let log_with_secret = "Error connecting with token AKIAIOSFODNN7EXAMPLE and Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M";
    let redacted = redact_secrets(log_with_secret);

    assert!(!redacted.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(!redacted.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
    assert!(redacted.contains("[REDACTED"));
}
