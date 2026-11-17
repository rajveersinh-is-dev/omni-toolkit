use omni_core::{OmniError, OmniResult};

pub struct ResourceLimits {
    pub max_bytes: usize,
    pub max_ratio: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_bytes: 500 * 1024 * 1024, // 500 MB
            max_ratio: 100,               // max 100x expansion ratio
        }
    }
}

impl ResourceLimits {
    pub fn check_decompression(&self, compressed_len: usize, uncompressed_len: usize) -> OmniResult<()> {
        if uncompressed_len > self.max_bytes {
            return Err(OmniError::Security(format!(
                "Decompressed size ({} bytes) exceeds maximum limit ({} bytes)",
                uncompressed_len, self.max_bytes
            )));
        }

        if compressed_len > 0 && (uncompressed_len / compressed_len) > self.max_ratio {
            return Err(OmniError::Security(format!(
                "Decompression ratio ({}x) exceeds maximum allowable safety ratio ({}x) — possible archive bomb",
                uncompressed_len / compressed_len,
                self.max_ratio
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
    }

    #[test]
    fn test_bomb_ratio_rejected() {
        let limits = ResourceLimits::default();
        assert!(limits.check_decompression(10, 10000).is_err());
    }
}
