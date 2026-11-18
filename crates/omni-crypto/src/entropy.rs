use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
};
use serde_json::Value;

// ======================== SHANNON ENTROPY ========================
pub struct ShannonEntropyOp;

#[async_trait]
impl Operation for ShannonEntropyOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "crypto.entropy.shannon",
            "Shannon Entropy Calculator",
            "Calculates byte-level Shannon information entropy (0.0 to 8.0 bits/byte) and distribution histogram",
            OperationCategory::Cryptography,
        )
        .with_types(vec![DataType::Bytes, DataType::Text], vec![DataType::Json])
        .with_status(FeatureStatus::Verified)
        .with_tags(vec!["crypto".into(), "entropy".into(), "forensics".into()])
    }

    async fn execute(
        &self,
        input: DataPayload,
        _config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let bytes = input.into_bytes();
        if bytes.is_empty() {
            return Ok(DataPayload::json(serde_json::json!({
                "entropy_bits_per_byte": 0.0,
                "total_bytes": 0,
                "assessment": "Empty buffer"
            })));
        }

        let mut frequencies = [0usize; 256];
        for &b in &bytes {
            frequencies[b as usize] += 1;
        }

        let total = bytes.len() as f64;
        let mut entropy: f64 = 0.0;
        let mut non_zero_counts = 0;

        for &count in &frequencies {
            if count > 0 {
                non_zero_counts += 1;
                let p = count as f64 / total;
                entropy -= p * p.log2();
            }
        }

        let assessment = if entropy > 7.9 {
            "Extremely high entropy (likely strong encryption, compressed stream, or random key material)"
        } else if entropy > 7.0 {
            "High entropy (likely compressed archive or compiled executable code)"
        } else if entropy > 4.5 {
            "Moderate entropy (typical formatted code or English prose)"
        } else {
            "Low entropy (structured data, repetitive pattern, or sparse binary)"
        };

        let res = serde_json::json!({
            "entropy_bits_per_byte": (entropy * 10000.0).round() / 10000.0,
            "max_possible_entropy": 8.0,
            "total_bytes": bytes.len(),
            "distinct_byte_values": non_zero_counts,
            "assessment": assessment,
        });

        Ok(DataPayload::json(res))
    }
}

// ======================== LSB STEGANOGRAPHY ========================
pub struct LsbSteganographyOp;

#[async_trait]
impl Operation for LsbSteganographyOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "crypto.entropy.lsb_stego",
            "LSB Steganography Injector & Extractor",
            "Hides or extracts secret messages within least significant bits of uncompressed audio/image byte streams",
            OperationCategory::Cryptography,
        )
        .with_types(vec![DataType::Bytes], vec![DataType::Bytes, DataType::Text])
        .with_status(FeatureStatus::Verified)
        .with_tags(vec!["crypto".into(), "steganography".into(), "lsb".into()])
    }

    async fn execute(
        &self,
        input: DataPayload,
        config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let action = config
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("extract");
        let mut carrier_bytes = input.into_bytes();

        match action {
            "inject" => {
                let secret = config
                    .get("secret")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        OmniError::Validation("Missing 'secret' text to inject".into())
                    })?;
                let secret_bytes = secret.as_bytes();
                let secret_len = u32::try_from(secret_bytes.len()).map_err(|_| {
                    OmniError::Validation("Secret payload exceeds 4 GiB header capacity".into())
                })?;

                // Prepend 4 bytes length header
                let mut data_to_embed = secret_len.to_be_bytes().to_vec();
                data_to_embed.extend_from_slice(secret_bytes);

                let bits_needed = data_to_embed.len().saturating_mul(8);
                if carrier_bytes.len() < bits_needed {
                    return Err(OmniError::Validation(format!(
                        "Carrier payload too small. Need {} bytes, got {}",
                        bits_needed,
                        carrier_bytes.len()
                    )));
                }

                let mut bit_idx = 0;
                for byte in data_to_embed {
                    for b in (0..8).rev() {
                        let bit = (byte >> b) & 1;
                        carrier_bytes[bit_idx] = (carrier_bytes[bit_idx] & 0xFE) | bit;
                        bit_idx += 1;
                    }
                }

                Ok(DataPayload::bytes(carrier_bytes))
            }
            "extract" => {
                if carrier_bytes.len() < 32 {
                    return Err(OmniError::InvalidInput(
                        "Carrier stream too small to extract header".into(),
                    ));
                }

                // Extract 4 bytes length
                let mut len_bytes = [0u8; 4];
                let mut bit_idx = 0;
                for item in &mut len_bytes {
                    let mut b = 0u8;
                    for _ in 0..8 {
                        b = (b << 1) | (carrier_bytes[bit_idx] & 1);
                        bit_idx += 1;
                    }
                    *item = b;
                }
                let len = u32::from_be_bytes(len_bytes) as usize;

                // Remaining carrier bytes after the 32-bit length header
                let available_payload_bytes = (carrier_bytes.len() - 32) / 8;
                if len > available_payload_bytes {
                    return Err(OmniError::InvalidInput(
                        "No valid embedded secret found (length header out of bounds)".into(),
                    ));
                }

                let mut secret = Vec::with_capacity(len);
                for _ in 0..len {
                    let mut b = 0u8;
                    for _ in 0..8 {
                        b = (b << 1) | (carrier_bytes[bit_idx] & 1);
                        bit_idx += 1;
                    }
                    secret.push(b);
                }

                let text = String::from_utf8(secret).map_err(|e| {
                    OmniError::InvalidInput(format!("Extracted bytes not UTF-8: {e}"))
                })?;
                Ok(DataPayload::text(text))
            }
            _ => Err(OmniError::Validation(format!(
                "Unknown action '{}'",
                action
            ))),
        }
    }
}
