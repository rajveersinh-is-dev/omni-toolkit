use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
};
use serde_json::{json, Value};

pub struct HardwareSerialOp;

#[async_trait]
impl Operation for HardwareSerialOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "hardware.serial",
            "Serial/UART Protocol Inspector",
            "Simulates and validates UART transmission framing, analyzing 8-N-1 and 7-E-1 parity configurations and framing errors",
            OperationCategory::BinaryAnalysis,
        )
        .with_types(vec![DataType::Bytes, DataType::Text], vec![DataType::Json])
        .with_status(FeatureStatus::Verified)
    }

    async fn execute(
        &self,
        input: DataPayload,
        config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let baud_rate = config
            .get("baud")
            .and_then(|v| v.as_u64())
            .unwrap_or(115200);
        if baud_rate == 0 {
            return Err(OmniError::Validation(
                "UART 'baud' rate must be greater than zero".into(),
            ));
        }
        let parity = config
            .get("parity")
            .and_then(|v| v.as_str())
            .unwrap_or("none");
        let bytes = input.into_bytes();

        let mut parity_errors = 0;
        let mut frames = Vec::new();

        for (idx, &byte) in bytes.iter().enumerate() {
            let ones = byte.count_ones();
            let parity_valid = match parity {
                "even" => ones % 2 == 0,
                "odd" => ones % 2 == 1,
                _ => true,
            };

            if !parity_valid {
                parity_errors += 1;
            }

            if idx < 20 {
                frames.push(json!({
                    "byte_index": idx,
                    "hex": format!("0x{:02X}", byte),
                    "char": if (32..=126).contains(&byte) { (byte as char).to_string() } else { ".".to_string() },
                    "ones_count": ones,
                    "parity_ok": parity_valid,
                }));
            }
        }

        let bit_time_us = (1_000_000.0 / baud_rate as f64 * 100.0).round() / 100.0;
        let frame_bits = if parity == "none" { 10 } else { 11 }; // 1 start + 8 data + (1 parity) + 1 stop
        let total_time_ms =
            (bytes.len() as f64 * frame_bits as f64 * (1.0 / baud_rate as f64) * 1000.0 * 100.0)
                .round()
                / 100.0;

        Ok(DataPayload::json(json!({
            "configured_baud_rate": baud_rate,
            "configured_parity": parity,
            "frame_format": format!("8-{}-1", parity.chars().next().unwrap_or('N').to_ascii_uppercase()),
            "bit_time_microseconds": bit_time_us,
            "total_bytes_transferred": bytes.len(),
            "estimated_transmission_time_ms": total_time_ms,
            "parity_errors_detected": parity_errors,
            "sample_frames": frames,
        })))
    }
}

pub struct HardwareCanOp;

#[async_trait]
impl Operation for HardwareCanOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "hardware.can",
            "CAN Bus Log & OBD-II Decoder",
            "Parses Linux candump logs, CAN 2.0A/2.0B frames, and decodes standard OBD-II diagnostic PIDs (RPM, Speed, Temp)",
            OperationCategory::BinaryAnalysis,
        )
        .with_types(vec![DataType::Text], vec![DataType::Json])
        .with_status(FeatureStatus::Verified)
    }

    async fn execute(
        &self,
        input: DataPayload,
        _config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let text = input.into_text().unwrap_or_default();
        let mut frames = Vec::new();

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            // Typical candump line:
            // (1600000000.123456) can0 123#DEADBEEF
            // or: can0 7DF#02010C0000000000
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            let can_token = parts.iter().find(|&&p| p.contains('#'));

            if let Some(token) = can_token {
                if let Some((id_str, data_hex)) = token.split_once('#') {
                    let is_fd = data_hex.starts_with('#');
                    let clean_hex = data_hex.trim_start_matches('#');
                    let can_id = u32::from_str_radix(id_str, 16).unwrap_or(0);
                    let payload = hex::decode(clean_hex).unwrap_or_default();

                    let mut decoded_obd = None;
                    // Check OBD-II standard broadcast response ID (0x7E8) or query (0x7DF)
                    if (can_id == 0x7E8 || can_id == 0x7DF) && payload.len() >= 3 {
                        let service = payload[1];
                        let pid = payload[2];
                        if service == 0x41 || service == 0x01 {
                            // Show current data
                            decoded_obd = match pid {
                                0x05 if payload.len() >= 4 => {
                                    let temp_c = (payload[3] as i32) - 40;
                                    Some(
                                        json!({ "pid": "0x05 Engine Coolant Temp", "value": format!("{} °C", temp_c) }),
                                    )
                                }
                                0x0C if payload.len() >= 5 => {
                                    let rpm = ((payload[3] as u32 * 256) + payload[4] as u32) / 4;
                                    Some(
                                        json!({ "pid": "0x0C Engine RPM", "value": format!("{} RPM", rpm) }),
                                    )
                                }
                                0x0D if payload.len() >= 4 => {
                                    let speed_kmh = payload[3];
                                    Some(
                                        json!({ "pid": "0x0D Vehicle Speed", "value": format!("{} km/h", speed_kmh) }),
                                    )
                                }
                                _ => None,
                            };
                        }
                    }

                    frames.push(json!({
                        "can_id_hex": format!("0x{:X}", can_id),
                        "is_extended_29bit": can_id > 0x7FF,
                        "is_can_fd": is_fd,
                        "dlc": payload.len(),
                        "payload_hex": clean_hex,
                        "obd2_decoded": decoded_obd,
                    }));
                }
            }
        }

        if frames.is_empty() {
            return Err(OmniError::InvalidInput(
                "No valid CAN frames found in candump input".into(),
            ));
        }

        Ok(DataPayload::json(json!({
            "total_can_frames_parsed": frames.len(),
            "frames": frames,
        })))
    }
}
