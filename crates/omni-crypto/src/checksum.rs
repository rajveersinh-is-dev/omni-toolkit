use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use serde_json::Value;

pub struct ChecksumOp {
    pub algorithm: String,
}

#[async_trait]
impl Operation for ChecksumOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            format!("checksum.{}", self.algorithm.to_lowercase()),
            format!("Checksum ({})", self.algorithm.to_uppercase()),
            format!("Calculates {} verification checksum", self.algorithm),
            OperationCategory::Cryptography,
        )
        .with_types(vec![DataType::Bytes, DataType::Text], vec![DataType::Text])
        .with_status(FeatureStatus::Verified)
        .with_tags(vec!["checksum".into(), self.algorithm.to_lowercase()])
    }

    async fn execute(
        &self,
        input: DataPayload,
        _config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let bytes = input.into_bytes();
        let result = match self.algorithm.to_lowercase().as_str() {
            "crc8" => {
                let mut crc: u8 = 0;
                for &b in &bytes {
                    crc ^= b;
                    for _ in 0..8 {
                        if (crc & 0x80) != 0 {
                            crc = (crc << 1) ^ 0x07; // SMBus polynomial
                        } else {
                            crc <<= 1;
                        }
                    }
                }
                format!("{:02x}", crc)
            }
            "crc16" => {
                let mut crc: u16 = 0xFFFF;
                for &b in &bytes {
                    crc ^= b as u16;
                    for _ in 0..8 {
                        if (crc & 1) != 0 {
                            crc = (crc >> 1) ^ 0xA001; // CRC-16-IBM
                        } else {
                            crc >>= 1;
                        }
                    }
                }
                format!("{:04x}", crc)
            }
            "crc32" | "crc32_ieee" => {
                let crc = crc32fast::hash(&bytes);
                format!("{:08x}", crc)
            }
            "crc32_castagnoli" => {
                // Castagnoli 0x1EDC6F41 polynomial
                let mut crc: u32 = 0xFFFFFFFF;
                for &b in &bytes {
                    crc ^= b as u32;
                    for _ in 0..8 {
                        crc = if (crc & 1) != 0 {
                            (crc >> 1) ^ 0x82F63B78
                        } else {
                            crc >> 1
                        };
                    }
                }
                format!("{:08x}", !crc)
            }
            "crc64" => {
                // ECMA-182 polynomial 0x42F0E1EBA9EA3693
                let mut crc: u64 = 0xFFFFFFFFFFFFFFFF;
                for &b in &bytes {
                    crc ^= (b as u64) << 56;
                    for _ in 0..8 {
                        crc = if (crc & 0x8000000000000000) != 0 {
                            (crc << 1) ^ 0x42F0E1EBA9EA3693
                        } else {
                            crc << 1
                        };
                    }
                }
                format!("{:016x}", !crc)
            }
            "adler32" => {
                let adler = adler::adler32_slice(&bytes);
                format!("{:08x}", adler)
            }
            "fletcher16" => {
                let mut sum1: u16 = 0;
                let mut sum2: u16 = 0;
                for &b in &bytes {
                    sum1 = (sum1 + b as u16) % 255;
                    sum2 = (sum2 + sum1) % 255;
                }
                format!("{:04x}", (sum2 << 8) | sum1)
            }
            "fletcher32" => {
                let mut sum1: u32 = 0xFFFF;
                let mut sum2: u32 = 0xFFFF;
                let mut i = 0;
                while i < bytes.len() {
                    let remaining_words = (bytes.len() - i).div_ceil(2);
                    let tlen = remaining_words.min(360);
                    for _ in 0..tlen {
                        let word = if i + 1 < bytes.len() {
                            ((bytes[i] as u32) << 8) | (bytes[i + 1] as u32)
                        } else {
                            (bytes[i] as u32) << 8
                        };
                        sum1 += word;
                        sum2 += sum1;
                        i += 2;
                    }
                    sum1 = (sum1 & 0xFFFF) + (sum1 >> 16);
                    sum2 = (sum2 & 0xFFFF) + (sum2 >> 16);
                }
                sum1 = (sum1 & 0xFFFF) + (sum1 >> 16);
                sum2 = (sum2 & 0xFFFF) + (sum2 >> 16);
                format!("{:08x}", (sum2 << 16) | sum1)
            }
            _ => format!("{:08x}", crc32fast::hash(&bytes)),
        };

        Ok(DataPayload::text(result))
    }
}
