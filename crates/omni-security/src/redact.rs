use regex::Regex;
use std::sync::LazyLock;

static PEM_PRIVATE_KEY_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----")
        .expect("valid regex")
});

static AWS_KEY_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b").expect("valid regex")
});

static GITHUB_TOKEN_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b").expect("valid regex")
});

static BEARER_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{16,}").expect("valid regex")
});

static GENERIC_SECRET_KV_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(password|passwd|secret|api_key|apikey|access_token)\s*[:=]\s*[^\s,;'\x22]{4,}")
        .expect("valid regex")
});

static WINDOWS_USER_PATH_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)[A-Z]:\\Users\\[^\\\s]+").expect("valid regex")
});

static UNIX_USER_PATH_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"/(home|Users)/[^/\s]+").expect("valid regex")
});

/// Redacts private keys, cloud credentials, bearer tokens, and secret key-value pairs.
pub fn redact_secrets(input: &str) -> String {
    let s = PEM_PRIVATE_KEY_REGEX.replace_all(input, "[REDACTED_PRIVATE_KEY]");
    let s = AWS_KEY_REGEX.replace_all(&s, "[REDACTED_AWS_KEY]");
    let s = GITHUB_TOKEN_REGEX.replace_all(&s, "[REDACTED_GITHUB_TOKEN]");
    let s = BEARER_REGEX.replace_all(&s, "Bearer [REDACTED_TOKEN]");
    let s = GENERIC_SECRET_KV_REGEX.replace_all(&s, "$1=[REDACTED]");
    s.into_owned()
}

/// Redacts both secrets and local user filesystem home paths before exposing error messages over APIs.
pub fn sanitize_error_message(input: &str) -> String {
    let s = redact_secrets(input);
    let s = WINDOWS_USER_PATH_REGEX.replace_all(&s, "<USER_HOME>");
    let s = UNIX_USER_PATH_REGEX.replace_all(&s, "<USER_HOME>");
    s.into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_private_key() {
        let fake_key =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----";
        let text = format!("Debug log with key: {}", fake_key);
        let redacted = redact_secrets(&text);
        assert!(!redacted.contains("MIIEow"));
        assert!(redacted.contains("[REDACTED_PRIVATE_KEY]"));
    }

    #[test]
    fn test_redact_aws_and_github_and_kv() {
        let text = "AWS=AKIAIOSFODNN7EXAMPLE gh=ghp_1234567890abcdef1234567890 password=supersecret";
        let redacted = redact_secrets(text);
        assert!(!redacted.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!redacted.contains("ghp_1234567890"));
        assert!(!redacted.contains("supersecret"));
    }

    #[test]
    fn test_sanitize_error_redacts_home_paths() {
        let msg = r"IO error reading C:\Users\alice\secret\file.txt and /home/bob/data.db";
        let sanitized = sanitize_error_message(msg);
        assert!(!sanitized.contains("alice"));
        assert!(!sanitized.contains("bob"));
        assert!(sanitized.contains("<USER_HOME>"));
    }
}
