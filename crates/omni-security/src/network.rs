use omni_core::{OmniError, OmniResult};
use std::net::IpAddr;

pub fn validate_network_target(target: &str, allow_external: bool) -> OmniResult<()> {
    if allow_external {
        return Ok(());
    }

    if target == "localhost" || target == "127.0.0.1" || target == "::1" {
        return Ok(());
    }

    if let Ok(ip) = target.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                if v4.is_loopback() || v4.is_private() {
                    return Ok(());
                }
            }
            IpAddr::V6(v6) => {
                if v6.is_loopback() {
                    return Ok(());
                }
            }
        }
    }

    Err(OmniError::Security(format!(
        "Target '{}' is external. Security policy requires explicit authorization for external network diagnostics.",
        target
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loopback_allowed() {
        assert!(validate_network_target("127.0.0.1", false).is_ok());
        assert!(validate_network_target("localhost", false).is_ok());
        assert!(validate_network_target("192.168.1.50", false).is_ok());
    }

    #[test]
    fn test_external_rejected_without_flag() {
        assert!(validate_network_target("8.8.8.8", false).is_err());
        assert!(validate_network_target("example.com", false).is_err());
        assert!(validate_network_target("8.8.8.8", true).is_ok());
    }
}
