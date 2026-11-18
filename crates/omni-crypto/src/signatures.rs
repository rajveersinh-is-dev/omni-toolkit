use hmac::{Hmac, Mac};
use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;
type HmacSha1 = Hmac<sha1::Sha1>;

pub struct SignaturesOp;

fn hmac_sha256_bytes(key: &[u8], data: &[u8]) -> OmniResult<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|e| OmniError::Execution {
        operation: "hmac_sha256".into(),
        message: e.to_string(),
    })?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

#[async_trait]
impl Operation for SignaturesOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "crypto.auth_signatures",
            "Signature & Auth Utilities",
            "Generates AWS SigV4, OAuth 1.0a HMAC signatures, and PKCE Code Verifiers / Challenges (RFC 7636)",
            OperationCategory::Cryptography,
        )
        .with_types(vec![DataType::Text, DataType::Json], vec![DataType::Json])
        .with_status(FeatureStatus::Verified)
        .with_tags(vec!["crypto".into(), "auth".into(), "pkce".into(), "sigv4".into(), "oauth".into()])
    }

    async fn execute(
        &self,
        _input: DataPayload,
        config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let auth_type = config
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("pkce");

        match auth_type {
            "pkce" => {
                // Generate 32 cryptographically random bytes for code_verifier
                let mut verifier_bytes = [0u8; 32];
                use rand::RngCore;
                rand::thread_rng().fill_bytes(&mut verifier_bytes);
                use base64::prelude::*;
                let code_verifier = BASE64_URL_SAFE_NO_PAD.encode(verifier_bytes);

                // SHA256 of code_verifier gives code_challenge (S256)
                let challenge_hash = Sha256::digest(code_verifier.as_bytes());
                let code_challenge = BASE64_URL_SAFE_NO_PAD.encode(challenge_hash);

                let res = serde_json::json!({
                    "code_verifier": code_verifier,
                    "code_challenge": code_challenge,
                    "code_challenge_method": "S256"
                });
                Ok(DataPayload::json(res))
            }
            "aws_sigv4" => {
                let secret_key = config
                    .get("secret_key")
                    .and_then(|v| v.as_str())
                    .unwrap_or("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
                let date = config
                    .get("date")
                    .and_then(|v| v.as_str())
                    .unwrap_or("20261117");
                let region = config
                    .get("region")
                    .and_then(|v| v.as_str())
                    .unwrap_or("us-east-1");
                let service = config
                    .get("service")
                    .and_then(|v| v.as_str())
                    .unwrap_or("s3");
                let string_to_sign = config
                    .get("string_to_sign")
                    .and_then(|v| v.as_str())
                    .unwrap_or("AWS4-HMAC-SHA256\n...");

                // Derive signing key: kSecret -> kDate -> kRegion -> kService -> kSigning
                let k_secret = format!("AWS4{}", secret_key);
                let k_date = hmac_sha256_bytes(k_secret.as_bytes(), date.as_bytes())?;
                let k_region = hmac_sha256_bytes(&k_date, region.as_bytes())?;
                let k_service = hmac_sha256_bytes(&k_region, service.as_bytes())?;
                let k_signing = hmac_sha256_bytes(&k_service, b"aws4_request")?;
                let sig_bytes = hmac_sha256_bytes(&k_signing, string_to_sign.as_bytes())?;
                let signature = hex::encode(sig_bytes);

                let res = serde_json::json!({
                    "signature": signature,
                    "date": date,
                    "region": region,
                    "service": service,
                });
                Ok(DataPayload::json(res))
            }
            "oauth1a" => {
                use base64::prelude::*;
                let consumer_secret = config
                    .get("consumer_secret")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let token_secret = config
                    .get("token_secret")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let base_string = config
                    .get("base_string")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        OmniError::Validation("OAuth 1.0a requires 'base_string' in config".into())
                    })?;
                let method = config
                    .get("method")
                    .and_then(|v| v.as_str())
                    .unwrap_or("HMAC-SHA1");
                let signing_key = format!("{}&{}", consumer_secret, token_secret);

                let sig_b64 =
                    match method {
                        "HMAC-SHA256" => {
                            let sig =
                                hmac_sha256_bytes(signing_key.as_bytes(), base_string.as_bytes())?;
                            BASE64_STANDARD.encode(sig)
                        }
                        "HMAC-SHA1" => {
                            let mut mac = HmacSha1::new_from_slice(signing_key.as_bytes())
                                .map_err(|e| OmniError::Execution {
                                    operation: "oauth1a".into(),
                                    message: e.to_string(),
                                })?;
                            mac.update(base_string.as_bytes());
                            BASE64_STANDARD.encode(mac.finalize().into_bytes())
                        }
                        other => {
                            return Err(OmniError::Validation(format!(
                                "Unsupported OAuth 1.0a method '{}' (use HMAC-SHA1 or HMAC-SHA256)",
                                other
                            )));
                        }
                    };

                Ok(DataPayload::json(serde_json::json!({
                    "signature": sig_b64,
                    "method": method,
                })))
            }
            _ => Err(OmniError::Validation(format!(
                "Unsupported signature type '{}'",
                auth_type
            ))),
        }
    }
}
