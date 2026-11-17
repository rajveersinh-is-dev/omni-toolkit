use regex::Regex;
use std::sync::LazyLock;

static PEM_PRIVATE_KEY_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----")
        .expect("valid regex")
});

static AWS_KEY_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b").expect("valid regex")
});

static BEARER_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}").expect("valid regex")
});

pub fn redact_secrets(input: &str) -> String {
    let s = PEM_PRIVATE_KEY_REGEX.replace_all(input, "[REDACTED_PRIVATE_KEY]");
    let s = AWS_KEY_REGEX.replace_all(&s, "[REDACTED_AWS_KEY]");
    let s = BEARER_REGEX.replace_all(&s, "Bearer [REDACTED_TOKEN]");
    s.into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_private_key() {
        let fake_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----";
        let text = format!("Debug log with key: {}", fake_key);
        let redacted = redact_secrets(&text);
        assert!(!redacted.contains("MIIEow"));
        assert!(redacted.contains("[REDACTED_PRIVATE_KEY]"));
    }

    #[test]
    fn test_redact_aws_key() {
        let text = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let redacted = redact_secrets(text);
        assert!(!redacted.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(redacted.contains("[REDACTED_AWS_KEY]"));
    }
}
