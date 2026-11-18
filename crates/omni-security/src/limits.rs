use omni_core::{OmniError, OmniResult};

#[derive(Debug, Clone)]
pub struct ResourceLimits {
    pub max_bytes: usize,
    pub max_ratio: usize,
    pub max_nesting_depth: usize,
    pub max_request_bytes: usize,
    pub max_concurrent_jobs: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_bytes: 500 * 1024 * 1024, // 500 MB
            max_ratio: 100,               // max 100x expansion ratio
            max_nesting_depth: 64,
            max_request_bytes: 16 * 1024 * 1024, // 16 MB API request limit
            max_concurrent_jobs: 16,
        }
    }
}

impl ResourceLimits {
    pub fn check_size(&self, size_bytes: usize) -> OmniResult<()> {
        if size_bytes > self.max_bytes {
            return Err(OmniError::Security(format!(
                "Payload size ({} bytes) exceeds maximum limit ({} bytes)",
                size_bytes, self.max_bytes
            )));
        }
        Ok(())
    }

    pub fn check_nesting_depth(&self, depth: usize) -> OmniResult<()> {
        if depth > self.max_nesting_depth {
            return Err(OmniError::Security(format!(
                "Nesting depth ({}) exceeds maximum limit ({})",
                depth, self.max_nesting_depth
            )));
        }
        Ok(())
    }

    /// Overflow-safe and division-truncation-safe decompression bomb verification.
    pub fn check_decompression(
        &self,
        compressed_len: usize,
        uncompressed_len: usize,
    ) -> OmniResult<()> {
        if uncompressed_len > self.max_bytes {
            return Err(OmniError::Security(format!(
                "Decompressed size ({} bytes) exceeds maximum limit ({} bytes)",
                uncompressed_len, self.max_bytes
            )));
        }

        if compressed_len == 0 && uncompressed_len > 0 {
            return Err(OmniError::Security(
                "Zero-byte compressed stream claiming non-zero uncompressed payload rejected"
                    .into(),
            ));
        }

        let max_allowed = (compressed_len as u128).saturating_mul(self.max_ratio as u128);
        if (uncompressed_len as u128) > max_allowed {
            let ratio = uncompressed_len as f64 / compressed_len.max(1) as f64;
            return Err(OmniError::Security(format!(
                "Decompression ratio ({:.1}x) exceeds maximum allowable safety ratio ({}x) — possible archive bomb",
                ratio, self.max_ratio
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_decompression() {
        let limits = ResourceLimits::default();
        assert!(limits.check_decompression(1000, 5000).is_ok());
        assert!(limits.check_decompression(10, 1000).is_ok()); // exactly 100x
    }

    #[test]
    fn test_bomb_ratio_rejected_without_integer_truncation() {
        let limits = ResourceLimits::default();
        assert!(limits.check_decompression(10, 10000).is_err());
        // Previously 1009 / 10 == 100 in integer division would have bypassed check!
        assert!(limits.check_decompression(10, 1009).is_err());
        // Zero compressed length with non-zero uncompressed length must be rejected
        assert!(limits.check_decompression(0, 1).is_err());
    }
}
