use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniError, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use serde_json::Value;

pub struct JwtDebuggerOp;

#[async_trait]
impl Operation for JwtDebuggerOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "crypto.jwt.debugger",
            "JWT / JWS Debugger",
            "Decodes, inspects claims, verifies offline signatures, and demonstrates token tampering",
            OperationCategory::Cryptography,
        )
        .with_types(vec![DataType::Text], vec![DataType::Json])
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let token = input.into_text()?;
        let parts: Vec<&str> = token.trim().split('.').collect();
        if parts.len() < 2 {
            return Err(OmniError::InvalidInput("Malformed JWT: must contain at least 2 dot-separated parts".into()));
        }

        use base64::prelude::*;
        let header_bytes = BASE64_URL_SAFE_NO_PAD.decode(parts[0])
            .map_err(|e| OmniError::InvalidInput(format!("Invalid base64 in JWT header: {e}")))?;
        let header: Value = serde_json::from_slice(&header_bytes)
            .map_err(|e| OmniError::InvalidInput(format!("Invalid JSON in JWT header: {e}")))?;

        let payload_bytes = BASE64_URL_SAFE_NO_PAD.decode(parts[1])
            .map_err(|e| OmniError::InvalidInput(format!("Invalid base64 in JWT payload: {e}")))?;
        let payload: Value = serde_json::from_slice(&payload_bytes)
            .map_err(|e| OmniError::InvalidInput(format!("Invalid JSON in JWT payload: {e}")))?;

        let signature_present = parts.len() == 3;
        let mut verified = false;
        let mut verification_error = None;

        if let Some(secret) = config.get("secret").and_then(|v| v.as_str()) {
            if signature_present {
                use hmac::{Hmac, Mac};
                use sha2::Sha256;
                type HmacSha256 = Hmac<Sha256>;

                if let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) {
                    let signed_content = format!("{}.{}", parts[0], parts[1]);
                    mac.update(signed_content.as_bytes());
                    if let Ok(sig_bytes) = BASE64_URL_SAFE_NO_PAD.decode(parts[2]) {
                        if mac.verify_slice(&sig_bytes).is_ok() {
                            verified = true;
                        } else {
                            verification_error = Some("Signature mismatch".to_string());
                        }
                    } else {
                        verification_error = Some("Malformed signature base64".to_string());
                    }
                }
            }
        }

        let is_tampered_demo = config.get("tamper_claims").and_then(|v| v.as_bool()).unwrap_or(false);
        let tampered_token = if is_tampered_demo {
            let mut tampered_payload = payload.clone();
            tampered_payload["role"] = serde_json::json!("admin");
            tampered_payload["exp"] = serde_json::json!(4102444800i64); // 2100 year
            let t_bytes = serde_json::to_vec(&tampered_payload).unwrap();
            let t_b64 = BASE64_URL_SAFE_NO_PAD.encode(&t_bytes);
            Some(format!("{}.{}.{}", parts[0], t_b64, parts.get(2).unwrap_or(&"")))
        } else {
            None
        };

        let result = serde_json::json!({
            "header": header,
            "payload": payload,
            "signature_present": signature_present,
            "verified": verified,
            "verification_error": verification_error,
            "tampered_token_demonstration": tampered_token,
        });

        Ok(DataPayload::json(result))
    }
}
