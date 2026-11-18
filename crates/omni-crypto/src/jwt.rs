use hmac::{Hmac, Mac};
use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
};
use serde_json::Value;
use sha2::{Sha256, Sha384, Sha512};

type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;

pub struct JwtDebuggerOp;

#[async_trait]
impl Operation for JwtDebuggerOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "crypto.jwt.debugger",
            "JWT / JWS Debugger",
            "Decodes, inspects claims, verifies offline HS256/HS384/HS512 signatures with strict algorithm enforcement, and demonstrates token tampering",
            OperationCategory::Cryptography,
        )
        .with_types(vec![DataType::Text], vec![DataType::Json])
        .with_status(FeatureStatus::Verified)
        .with_tags(vec!["crypto".into(), "jwt".into(), "jws".into(), "auth".into()])
    }

    async fn execute(
        &self,
        input: DataPayload,
        config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let token = input.into_text()?;
        let parts: Vec<&str> = token.trim().split('.').collect();
        if parts.len() < 2 || parts.len() > 3 {
            return Err(OmniError::InvalidInput(
                "Malformed JWT: must contain 2 or 3 dot-separated parts".into(),
            ));
        }

        use base64::prelude::*;
        let header_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|e| OmniError::InvalidInput(format!("Invalid base64 in JWT header: {e}")))?;
        let header: Value = serde_json::from_slice(&header_bytes)
            .map_err(|e| OmniError::InvalidInput(format!("Invalid JSON in JWT header: {e}")))?;

        let payload_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|e| OmniError::InvalidInput(format!("Invalid base64 in JWT payload: {e}")))?;
        let payload: Value = serde_json::from_slice(&payload_bytes)
            .map_err(|e| OmniError::InvalidInput(format!("Invalid JSON in JWT payload: {e}")))?;

        let signature_present = parts.len() == 3 && !parts[2].is_empty();
        let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
        let mut verified = false;
        let mut verification_error = None;

        if let Some(secret) = config.get("secret").and_then(|v| v.as_str()) {
            if !signature_present {
                verification_error = Some("No signature present in JWT".to_string());
            } else if alg.eq_ignore_ascii_case("none") || alg.is_empty() {
                verification_error = Some(
                    "Rejected insecure or missing 'alg' header ('none' is never verified)".into(),
                );
            } else {
                let signed_content = format!("{}.{}", parts[0], parts[1]);
                match BASE64_URL_SAFE_NO_PAD.decode(parts[2]) {
                    Err(_) => {
                        verification_error = Some("Malformed signature base64".to_string());
                    }
                    Ok(sig_bytes) => {
                        let verify_res = match alg {
                            "HS256" => {
                                HmacSha256::new_from_slice(secret.as_bytes()).map(|mut m| {
                                    m.update(signed_content.as_bytes());
                                    m.verify_slice(&sig_bytes).is_ok()
                                })
                            }
                            "HS384" => {
                                HmacSha384::new_from_slice(secret.as_bytes()).map(|mut m| {
                                    m.update(signed_content.as_bytes());
                                    m.verify_slice(&sig_bytes).is_ok()
                                })
                            }
                            "HS512" => {
                                HmacSha512::new_from_slice(secret.as_bytes()).map(|mut m| {
                                    m.update(signed_content.as_bytes());
                                    m.verify_slice(&sig_bytes).is_ok()
                                })
                            }
                            other => {
                                verification_error = Some(format!(
                                    "Unsupported symmetric verification algorithm '{}' (supported: HS256, HS384, HS512)",
                                    other
                                ));
                                Ok(false)
                            }
                        };
                        if verification_error.is_none() {
                            match verify_res {
                                Ok(true) => verified = true,
                                Ok(false) => {
                                    verification_error = Some("Signature mismatch".to_string())
                                }
                                Err(e) => {
                                    verification_error = Some(format!("HMAC key error: {e}"));
                                }
                            }
                        }
                    }
                }
            }
        }

        let is_tampered_demo = config
            .get("tamper_claims")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let tampered_token = if is_tampered_demo {
            let mut tampered_payload = payload.clone();
            tampered_payload["role"] = serde_json::json!("admin");
            tampered_payload["exp"] = serde_json::json!(4102444800i64); // 2100 year
            let t_bytes =
                serde_json::to_vec(&tampered_payload).map_err(|e| OmniError::Execution {
                    operation: "jwt_tamper".into(),
                    message: e.to_string(),
                })?;
            let t_b64 = BASE64_URL_SAFE_NO_PAD.encode(&t_bytes);
            Some(format!(
                "{}.{}.{}",
                parts[0],
                t_b64,
                parts.get(2).unwrap_or(&"")
            ))
        } else {
            None
        };

        let result = serde_json::json!({
            "header": header,
            "payload": payload,
            "algorithm": alg,
            "signature_present": signature_present,
            "verified": verified,
            "verification_error": verification_error,
            "tampered_token_demonstration": tampered_token,
        });

        Ok(DataPayload::json(result))
    }
}
