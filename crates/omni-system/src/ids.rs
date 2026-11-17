use chrono::{DateTime, Utc};
use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniError, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use serde_json::{json, Value};
use uuid::Uuid;

pub struct UniversalIdsOp;

// Crockford Base32 alphabet for ULID
const CROCKFORD_ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn generate_ulid() -> String {
    let now_ms = Utc::now().timestamp_millis() as u64;
    let mut chars = Vec::with_capacity(26);

    // 10 chars for 48-bit timestamp
    let mut ts = now_ms;
    for _ in 0..10 {
        chars.push(CROCKFORD_ALPHABET[(ts & 0x1F) as usize] as char);
        ts >>= 5;
    }
    chars.reverse();

    // 16 chars for 80-bit pseudo-randomness
    let rand_val = uuid::Uuid::new_v4();
    let r_bytes = rand_val.as_bytes();
    for i in 0..16 {
        chars.push(CROCKFORD_ALPHABET[(r_bytes[i % 16] % 32) as usize] as char);
    }

    chars.into_iter().collect()
}

fn decode_snowflake(id: u64, epoch_ms: u64) -> Value {
    let timestamp_ms = (id >> 22) + epoch_ms;
    let internal_worker_id = (id & 0x3E0000) >> 17;
    let internal_process_id = (id & 0x1F000) >> 12;
    let sequence = id & 0xFFF;

    let dt = DateTime::from_timestamp_millis(timestamp_ms as i64).unwrap_or_default();

    json!({
        "snowflake_id": id.to_string(),
        "timestamp_ms": timestamp_ms,
        "utc_time": dt.to_rfc3339(),
        "datacenter_id": internal_worker_id,
        "worker_process_id": internal_process_id,
        "sequence": sequence,
    })
}

#[async_trait]
impl Operation for UniversalIdsOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "system.ids",
            "Universal Identifier Toolkit",
            "Generates and inspects UUID (v4/v7), ULID, and decomposes 64-bit Twitter/Discord Snowflake IDs",
            OperationCategory::SystemDiagnostics,
        )
        .with_types(vec![DataType::Text, DataType::Json], vec![DataType::Json])
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let action = config.get("action").and_then(|v| v.as_str()).unwrap_or("generate");

        match action {
            "decode_snowflake" => {
                let id_str = config.get("id")
                    .and_then(|v| v.as_str())
                    .or_else(|| input.as_str().ok())
                    .unwrap_or("175928847299117063");

                let id: u64 = id_str.trim().parse().map_err(|_| OmniError::InvalidInput("Invalid numeric snowflake ID".into()))?;
                // Default Discord epoch (2015-01-01) = 1420070400000 ms
                let epoch = config.get("epoch_ms").and_then(|v| v.as_u64()).unwrap_or(1420070400000);
                Ok(DataPayload::json(decode_snowflake(id, epoch)))
            }
            "inspect_uuid" => {
                let u_str = config.get("uuid")
                    .and_then(|v| v.as_str())
                    .or_else(|| input.as_str().ok())
                    .unwrap_or("00000000-0000-0000-0000-000000000000");

                let u = Uuid::parse_str(u_str.trim())
                    .map_err(|e| OmniError::InvalidInput(format!("Invalid UUID: {e}")))?;

                let (ver_num, variant) = (u.get_version_num(), format!("{:?}", u.get_variant()));

                Ok(DataPayload::json(json!({
                    "uuid": u.to_string(),
                    "version": ver_num,
                    "variant": variant,
                    "hex_bytes": hex::encode(u.as_bytes()),
                })))
            }
            _ => {
                let id_type = config.get("type").and_then(|v| v.as_str()).unwrap_or("all");

                let v4 = Uuid::new_v4().to_string();
                let v7 = Uuid::now_v7().to_string();
                let ulid = generate_ulid();

                if id_type == "v7" {
                    Ok(DataPayload::json(json!({ "uuid_v7": v7 })))
                } else if id_type == "ulid" {
                    Ok(DataPayload::json(json!({ "ulid": ulid })))
                } else {
                    Ok(DataPayload::json(json!({
                        "uuid_v4_random": v4,
                        "uuid_v7_time_ordered": v7,
                        "ulid_lexicographical": ulid,
                    })))
                }
            }
        }
    }
}
