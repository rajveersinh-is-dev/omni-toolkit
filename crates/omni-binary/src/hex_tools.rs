use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
};
use serde_json::{json, Value};

pub struct BinaryHexOp;

#[async_trait]
impl Operation for BinaryHexOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "binary.hex",
            "Hex Editor & Bitwise Operations Engine",
            "Inspects, diffs, patches, byte-swaps, and performs bitwise transformations on raw binary streams",
            OperationCategory::BinaryAnalysis,
        )
        .with_types(
            vec![DataType::Bytes, DataType::Text],
            vec![DataType::Json, DataType::Bytes, DataType::Text],
        )
        .with_status(FeatureStatus::Verified)
        .with_tags(vec!["binary".into(), "hex".into(), "bitwise".into()])
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
            .unwrap_or("hexdump");
        let bytes = input.into_bytes();

        match action {
            "hexdump" => {
                let width_u64 = config.get("width").and_then(|v| v.as_u64()).unwrap_or(16);
                if !(1..=256).contains(&width_u64) {
                    return Err(OmniError::Validation(
                        "Hexdump 'width' must be between 1 and 256 bytes per line".into(),
                    ));
                }
                let bytes_per_line = width_u64 as usize;
                let mut lines = Vec::new();

                for (line_idx, chunk) in bytes.chunks(bytes_per_line).enumerate() {
                    let offset = line_idx * bytes_per_line;
                    let hex_part: Vec<String> =
                        chunk.iter().map(|b| format!("{:02X}", b)).collect();
                    let ascii_part: String = chunk
                        .iter()
                        .map(|&b| {
                            if (32..=126).contains(&b) {
                                b as char
                            } else {
                                '.'
                            }
                        })
                        .collect();

                    let padding = "   ".repeat(bytes_per_line - chunk.len());
                    lines.push(format!(
                        "{:08X}:  {}{}{}|{}|",
                        offset,
                        hex_part.join(" "),
                        padding,
                        if chunk.len() > 8 { " " } else { "" },
                        ascii_part
                    ));
                }

                Ok(DataPayload::text(lines.join("\n")))
            }
            "byte_swap" => {
                let word_u64 = config
                    .get("word_size")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(2);
                if !(1..=64).contains(&word_u64) {
                    return Err(OmniError::Validation(
                        "byte_swap 'word_size' must be between 1 and 64 bytes".into(),
                    ));
                }
                let word_size = word_u64 as usize;
                let mut swapped = bytes.clone();
                for chunk in swapped.chunks_exact_mut(word_size) {
                    chunk.reverse();
                }
                Ok(DataPayload::bytes(swapped))
            }
            "bitwise" => {
                let op = config.get("op").and_then(|v| v.as_str()).unwrap_or("xor");
                let key_str = config.get("key").and_then(|v| v.as_str()).unwrap_or("AA");
                let key = hex::decode(key_str)
                    .map_err(|e| OmniError::InvalidInput(format!("Invalid key hex: {e}")))?;
                if key.is_empty() {
                    return Err(OmniError::InvalidInput("Key cannot be empty".into()));
                }

                let mut out = bytes.clone();
                for (i, b) in out.iter_mut().enumerate() {
                    let k = key[i % key.len()];
                    match op {
                        "xor" => *b ^= k,
                        "and" => *b &= k,
                        "or" => *b |= k,
                        "not" => *b = !*b,
                        _ => {}
                    }
                }
                Ok(DataPayload::bytes(out))
            }
            "diff" => {
                let other_hex = config.get("other").and_then(|v| v.as_str()).unwrap_or("");
                let other_bytes = hex::decode(other_hex).unwrap_or_default();

                let mut diffs = Vec::new();
                let min_len = bytes.len().min(other_bytes.len());
                for i in 0..min_len {
                    if bytes[i] != other_bytes[i] {
                        diffs.push(json!({
                            "offset": i,
                            "a_hex": format!("{:02X}", bytes[i]),
                            "b_hex": format!("{:02X}", other_bytes[i]),
                        }));
                    }
                }

                Ok(DataPayload::json(json!({
                    "total_differences": diffs.len(),
                    "length_a": bytes.len(),
                    "length_b": other_bytes.len(),
                    "differences": diffs,
                })))
            }
            _ => Err(OmniError::InvalidInput(format!("Unknown action: {action}"))),
        }
    }
}

pub struct Ieee754VisualizerOp;

#[async_trait]
impl Operation for Ieee754VisualizerOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "binary.ieee754",
            "IEEE-754 Floating-Point Visualizer",
            "Decomposes 32-bit single and 64-bit double precision floats into sign, exponent, and mantissa components",
            OperationCategory::BinaryAnalysis,
        )
        .with_types(vec![DataType::Text, DataType::Json], vec![DataType::Json])
        .with_status(FeatureStatus::Verified)
        .with_tags(vec!["binary".into(), "ieee754".into(), "float".into()])
    }

    async fn execute(
        &self,
        input: DataPayload,
        config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let val_f64 = config
            .get("value")
            .and_then(|v| v.as_f64())
            .or_else(|| {
                input
                    .as_str()
                    .ok()
                    .and_then(|s| s.trim().parse::<f64>().ok())
            })
            .unwrap_or(std::f64::consts::PI);

        let precision = config
            .get("precision")
            .and_then(|v| v.as_str())
            .unwrap_or("f64");

        if precision == "f32" {
            let val_f32 = val_f64 as f32;
            let bits = val_f32.to_bits();
            let sign = (bits >> 31) & 1;
            let exponent = (bits >> 23) & 0xFF;
            let mantissa = bits & 0x7FFFFF;

            let classification = if exponent == 0xFF {
                if mantissa == 0 {
                    "Infinity"
                } else {
                    "NaN"
                }
            } else if exponent == 0 {
                if mantissa == 0 {
                    "Zero"
                } else {
                    "Subnormal (Denormalized)"
                }
            } else {
                "Normalized"
            };

            let exp_unbiased = if exponent == 0 {
                -126
            } else {
                (exponent as i32) - 127
            };
            let fraction = mantissa as f64 / 8388608.0; // 2^23
            let significand = if exponent == 0 {
                fraction
            } else {
                1.0 + fraction
            };

            Ok(DataPayload::json(json!({
                "format": "IEEE-754 Binary32 (Single Precision)",
                "value": val_f32,
                "hex": format!("0x{:08X}", bits),
                "sign_bit": sign,
                "exponent_bits": format!("{:08b}", exponent),
                "exponent_raw": exponent,
                "exponent_unbiased": exp_unbiased,
                "mantissa_bits": format!("{:023b}", mantissa),
                "mantissa_fraction": fraction,
                "significand": significand,
                "classification": classification,
                "formula": format!("(-1)^{} * 2^({}) * {}", sign, exp_unbiased, significand),
            })))
        } else {
            let bits = val_f64.to_bits();
            let sign = (bits >> 63) & 1;
            let exponent = (bits >> 52) & 0x7FF;
            let mantissa = bits & 0xFFFFFFFFFFFFF;

            let classification = if exponent == 0x7FF {
                if mantissa == 0 {
                    "Infinity"
                } else {
                    "NaN"
                }
            } else if exponent == 0 {
                if mantissa == 0 {
                    "Zero"
                } else {
                    "Subnormal (Denormalized)"
                }
            } else {
                "Normalized"
            };

            let exp_unbiased = if exponent == 0 {
                -1022
            } else {
                (exponent as i64) - 1023
            };
            let fraction = mantissa as f64 / 4503599627370496.0; // 2^52
            let significand = if exponent == 0 {
                fraction
            } else {
                1.0 + fraction
            };

            Ok(DataPayload::json(json!({
                "format": "IEEE-754 Binary64 (Double Precision)",
                "value": val_f64,
                "hex": format!("0x{:016X}", bits),
                "sign_bit": sign,
                "exponent_bits": format!("{:011b}", exponent),
                "exponent_raw": exponent,
                "exponent_unbiased": exp_unbiased,
                "mantissa_bits": format!("{:052b}", mantissa),
                "mantissa_fraction": fraction,
                "significand": significand,
                "classification": classification,
                "formula": format!("(-1)^{} * 2^({}) * {}", sign, exp_unbiased, significand),
            })))
        }
    }
}
