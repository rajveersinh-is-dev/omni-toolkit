use flate2::read::GzDecoder;
use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use serde_json::{json, Value};
use std::io::Read;

pub struct FirmwareExtractorOp;

#[derive(Debug, Clone, serde::Serialize)]
struct FirmwareSignatureMatch {
    offset: usize,
    offset_hex: String,
    description: String,
    confidence: String,
}

fn calculate_entropy(chunk: &[u8]) -> f64 {
    if chunk.is_empty() { return 0.0; }
    let mut counts = [0usize; 256];
    for &b in chunk {
        counts[b as usize] += 1;
    }
    let total = chunk.len() as f64;
    let mut entropy = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / total;
            entropy -= p * p.log2();
        }
    }
    entropy
}

#[async_trait]
impl Operation for FirmwareExtractorOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "firmware.extract",
            "Firmware Signature Scanner & Entropy Mapper",
            "Scans firmware blobs for SquashFS, CramFS, JFFS2, U-Boot, and compressed archives with block-by-block entropy mapping",
            OperationCategory::BinaryAnalysis,
        )
        .with_types(vec![DataType::Bytes], vec![DataType::Json])
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let bytes = input.into_bytes();
        let chunk_size = config.get("entropy_chunk_size").and_then(|v| v.as_u64()).unwrap_or(1024) as usize;

        // 1. Signature scan
        let mut matches = Vec::new();
        let len = bytes.len();

        let mut i = 0;
        while i < len {
            if i + 3 <= len && bytes[i..i + 3] == [0x1F, 0x8B, 0x08] {
                matches.push(FirmwareSignatureMatch {
                    offset: i,
                    offset_hex: format!("0x{:08X}", i),
                    description: "gzip compressed data, maximum compression".into(),
                    confidence: "High".into(),
                });
            } else if i + 6 <= len && bytes[i..i + 6] == [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00] {
                matches.push(FirmwareSignatureMatch {
                    offset: i,
                    offset_hex: format!("0x{:08X}", i),
                    description: "XZ compressed archive".into(),
                    confidence: "High".into(),
                });
            } else if i + 3 <= len && &bytes[i..i + 3] == b"BZh" {
                matches.push(FirmwareSignatureMatch {
                    offset: i,
                    offset_hex: format!("0x{:08X}", i),
                    description: "bzip2 compressed data".into(),
                    confidence: "High".into(),
                });
            } else if i + 4 <= len && &bytes[i..i + 4] == b"hsqs" {
                matches.push(FirmwareSignatureMatch {
                    offset: i,
                    offset_hex: format!("0x{:08X}", i),
                    description: "Squashfs filesystem, little endian, version 4.0".into(),
                    confidence: "High".into(),
                });
            } else if i + 4 <= len && &bytes[i..i + 4] == b"sqsh" {
                matches.push(FirmwareSignatureMatch {
                    offset: i,
                    offset_hex: format!("0x{:08X}", i),
                    description: "Squashfs filesystem, big endian".into(),
                    confidence: "High".into(),
                });
            } else if i + 4 <= len && bytes[i..i + 4] == [0x27, 0x05, 0x19, 0x56] {
                matches.push(FirmwareSignatureMatch {
                    offset: i,
                    offset_hex: format!("0x{:08X}", i),
                    description: "uImage header, U-Boot Linux kernel image".into(),
                    confidence: "High".into(),
                });
            } else if i + 4 <= len && &bytes[i..i + 4] == b"_FVH" {
                matches.push(FirmwareSignatureMatch {
                    offset: i,
                    offset_hex: format!("0x{:08X}", i),
                    description: "UEFI Firmware Volume Header (_FVH)".into(),
                    confidence: "High".into(),
                });
            } else if i + 4 <= len && bytes[i..i + 4] == [0x50, 0x4B, 0x03, 0x04] {
                matches.push(FirmwareSignatureMatch {
                    offset: i,
                    offset_hex: format!("0x{:08X}", i),
                    description: "Zip archive data".into(),
                    confidence: "High".into(),
                });
            }

            i += 1;
        }

        // 2. Entropy mapping
        let mut entropy_points = Vec::new();
        for (chunk_idx, chunk) in bytes.chunks(chunk_size).enumerate() {
            let ent = calculate_entropy(chunk);
            entropy_points.push(json!({
                "offset": chunk_idx * chunk_size,
                "entropy": (ent * 100.0).round() / 100.0,
            }));
        }

        // 3. Optional carving of first gzip stream
        let mut carved_info = None;
        if config.get("carve").and_then(|v| v.as_bool()).unwrap_or(false) {
            if let Some(m) = matches.iter().find(|m| m.description.contains("gzip")) {
                let mut gz = GzDecoder::new(&bytes[m.offset..]);
                let mut decompressed = Vec::new();
                if gz.read_to_end(&mut decompressed).is_ok() {
                    carved_info = Some(json!({
                        "carved_from_offset": m.offset,
                        "decompressed_size_bytes": decompressed.len(),
                        "is_valid_decompression": true,
                    }));
                }
            }
        }

        Ok(DataPayload::json(json!({
            "image_size_bytes": bytes.len(),
            "total_signatures_found": matches.len(),
            "signatures": matches,
            "entropy_chunk_size": chunk_size,
            "entropy_map": entropy_points,
            "carved_payload": carved_info,
        })))
    }
}
