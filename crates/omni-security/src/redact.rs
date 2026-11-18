use regex::Regex;
use std::borrow::Cow;
use std::sync::LazyLock;

static PEM_PRIVATE_KEY_REGEX: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----")
        .ok()
});

static AWS_KEY_REGEX: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b").ok());

static GITHUB_TOKEN_REGEX: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b").ok());

static BEARER_REGEX: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{16,}").ok());

static GENERIC_SECRET_KV_REGEX: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(password|passwd|secret|api_key|apikey|access_token)\s*[:=]\s*[^\s,;'\x22]{4,}",
    )
    .ok()
});

static WINDOWS_USER_PATH_REGEX: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?i)[A-Z]:\\Users\\[^\\\s]+").ok());

static UNIX_USER_PATH_REGEX: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"/(home|Users)/[^/\s]+").ok());

fn replace_opt<'a>(re: &Option<Regex>, input: &'a str, rep: &str) -> Cow<'a, str> {
    match re {
        Some(r) => r.replace_all(input, rep),
        None => Cow::Borrowed(input),
    }
}

/// Redacts private keys, cloud credentials, bearer tokens, and secret key-value pairs.
pub fn redact_secrets(input: &str) -> String {
    let s = replace_opt(&PEM_PRIVATE_KEY_REGEX, input, "[REDACTED_PRIVATE_KEY]");
    let s = replace_opt(&AWS_KEY_REGEX, &s, "[REDACTED_AWS_KEY]");
    let s = replace_opt(&GITHUB_TOKEN_REGEX, &s, "[REDACTED_GITHUB_TOKEN]");
    let s = replace_opt(&BEARER_REGEX, &s, "Bearer [REDACTED_TOKEN]");
    let s = replace_opt(&GENERIC_SECRET_KV_REGEX, &s, "$1=[REDACTED]");
    s.into_owned()
}

/// Redacts both secrets and local user filesystem home paths before exposing error messages over APIs.
pub fn sanitize_error_message(input: &str) -> String {
    let s = redact_secrets(input);
    let s = replace_opt(&WINDOWS_USER_PATH_REGEX, &s, "<USER_HOME>");
    let s = replace_opt(&UNIX_USER_PATH_REGEX, &s, "<USER_HOME>");
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
        let text =
            "AWS=AKIAIOSFODNN7EXAMPLE gh=ghp_1234567890abcdef1234567890 password=supersecret";
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
