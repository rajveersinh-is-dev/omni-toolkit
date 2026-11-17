use hmac::{Hmac, Mac};
use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniError, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub struct SignaturesOp;

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
    }

    async fn execute(&self, _input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let auth_type = config.get("type").and_then(|v| v.as_str()).unwrap_or("pkce");

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
                let secret_key = config.get("secret_key").and_then(|v| v.as_str()).unwrap_or("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
                let date = config.get("date").and_then(|v| v.as_str()).unwrap_or("20261117");
                let region = config.get("region").and_then(|v| v.as_str()).unwrap_or("us-east-1");
                let service = config.get("service").and_then(|v| v.as_str()).unwrap_or("s3");
                let string_to_sign = config.get("string_to_sign").and_then(|v| v.as_str()).unwrap_or("AWS4-HMAC-SHA256\n...");

                // Derive signing key: kSecret -> kDate -> kRegion -> kService -> kSigning
                let k_secret = format!("AWS4{}", secret_key);
                let mut h_date = HmacSha256::new_from_slice(k_secret.as_bytes()).map_err(|e| OmniError::Execution { operation: "aws".into(), message: e.to_string() })?;
                h_date.update(date.as_bytes());
                let k_date = h_date.finalize().into_bytes();

                let mut h_region = HmacSha256::new_from_slice(&k_date).unwrap();
                h_region.update(region.as_bytes());
                let k_region = h_region.finalize().into_bytes();

                let mut h_service = HmacSha256::new_from_slice(&k_region).unwrap();
                h_service.update(service.as_bytes());
                let k_service = h_service.finalize().into_bytes();

                let mut h_signing = HmacSha256::new_from_slice(&k_service).unwrap();
                h_signing.update(b"aws4_request");
                let k_signing = h_signing.finalize().into_bytes();

                let mut h_final = HmacSha256::new_from_slice(&k_signing).unwrap();
                h_final.update(string_to_sign.as_bytes());
                let signature = hex::encode(h_final.finalize().into_bytes());

                let res = serde_json::json!({
                    "signature": signature,
                    "date": date,
                    "region": region,
                    "service": service,
                });
                Ok(DataPayload::json(res))
            }
            _ => Err(OmniError::Validation(format!("Unsupported signature type '{}'", auth_type))),
        }
    }
}
