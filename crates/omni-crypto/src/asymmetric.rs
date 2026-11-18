use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
};
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use serde_json::Value;

// ======================== RSA TOOLKIT ========================
pub struct RsaOp;
#[async_trait]
impl Operation for RsaOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "crypto.asymmetric.rsa",
            "RSA Toolkit",
            "RSA key generation (1024-4096 bits) and OAEP encryption/decryption",
            OperationCategory::Cryptography,
        )
        .with_types(
            vec![DataType::Text, DataType::Bytes],
            vec![DataType::Text, DataType::Bytes, DataType::Json],
        )
        .with_status(FeatureStatus::Verified)
        .with_tags(vec!["crypto".into(), "asymmetric".into(), "rsa".into()])
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
            .unwrap_or("keygen");

        match action {
            "keygen" => {
                let bits_u64 = config.get("bits").and_then(|v| v.as_u64()).unwrap_or(2048);
                if !(1024..=4096).contains(&bits_u64) {
                    return Err(OmniError::Validation(
                        "RSA key size 'bits' must be between 1024 and 4096".into(),
                    ));
                }
                let bits = bits_u64 as usize;
                let mut rng = rand::thread_rng();
                let priv_key =
                    RsaPrivateKey::new(&mut rng, bits).map_err(|e| OmniError::Execution {
                        operation: "rsa_keygen".into(),
                        message: e.to_string(),
                    })?;
                let pub_key = RsaPublicKey::from(&priv_key);

                let priv_pem = priv_key
                    .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
                    .map_err(|e| OmniError::Execution {
                        operation: "rsa_pem".into(),
                        message: e.to_string(),
                    })?;
                let pub_pem = pub_key
                    .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
                    .map_err(|e| OmniError::Execution {
                        operation: "rsa_pem".into(),
                        message: e.to_string(),
                    })?;

                let res = serde_json::json!({
                    "bits": bits,
                    "private_key_pem": priv_pem.as_str(),
                    "public_key_pem": pub_pem.as_str(),
                });
                Ok(DataPayload::json(res))
            }
            "encrypt" => {
                let pub_pem = config
                    .get("public_key_pem")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        OmniError::Validation("Missing 'public_key_pem' in config".into())
                    })?;
                use rsa::pkcs8::DecodePublicKey;
                let pub_key = RsaPublicKey::from_public_key_pem(pub_pem)
                    .map_err(|e| OmniError::InvalidInput(format!("Invalid RSA public key: {e}")))?;

                let bytes = input.into_bytes();
                let mut rng = rand::thread_rng();
                let padding = Oaep::new::<sha2::Sha256>();
                let encrypted = pub_key.encrypt(&mut rng, padding, &bytes).map_err(|e| {
                    OmniError::Execution {
                        operation: "rsa_encrypt".into(),
                        message: e.to_string(),
                    }
                })?;

                Ok(DataPayload::bytes(encrypted))
            }
            "decrypt" => {
                let priv_pem = config
                    .get("private_key_pem")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        OmniError::Validation("Missing 'private_key_pem' in config".into())
                    })?;
                use rsa::pkcs8::DecodePrivateKey;
                let priv_key = RsaPrivateKey::from_pkcs8_pem(priv_pem).map_err(|e| {
                    OmniError::InvalidInput(format!("Invalid RSA private key: {e}"))
                })?;

                let bytes = input.into_bytes();
                let padding = Oaep::new::<sha2::Sha256>();
                let decrypted =
                    priv_key
                        .decrypt(padding, &bytes)
                        .map_err(|e| OmniError::Execution {
                            operation: "rsa_decrypt".into(),
                            message: e.to_string(),
                        })?;

                Ok(DataPayload::bytes(decrypted))
            }
            _ => Err(OmniError::Validation(format!(
                "Unknown RSA action '{}'",
                action
            ))),
        }
    }
}

// ======================== ED25519 SIGNING ========================
pub struct Ed25519Op;
#[async_trait]
impl Operation for Ed25519Op {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "crypto.asymmetric.ed25519",
            "Ed25519 Digital Signatures",
            "High-speed Ed25519 key generation, signature generation, and verification",
            OperationCategory::Cryptography,
        )
        .with_status(FeatureStatus::Verified)
        .with_tags(vec!["crypto".into(), "asymmetric".into(), "ed25519".into()])
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
            .unwrap_or("sign");

        match action {
            "keygen" => {
                let mut rng = rand::thread_rng();
                let signing_key = SigningKey::generate(&mut rng);
                let verifying_key = signing_key.verifying_key();

                let res = serde_json::json!({
                    "secret_key_hex": hex::encode(signing_key.to_bytes()),
                    "public_key_hex": hex::encode(verifying_key.to_bytes()),
                });
                Ok(DataPayload::json(res))
            }
            "sign" => {
                let secret_hex = config
                    .get("secret_key_hex")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        OmniError::Validation("Missing 'secret_key_hex' in config".into())
                    })?;
                let secret_bytes = hex::decode(secret_hex)
                    .map_err(|e| OmniError::InvalidInput(format!("Invalid secret key hex: {e}")))?;
                if secret_bytes.len() != 32 {
                    return Err(OmniError::Validation(
                        "Ed25519 secret key must be 32 bytes".into(),
                    ));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&secret_bytes);
                let signing_key = SigningKey::from_bytes(&arr);

                let data = input.into_bytes();
                let signature = signing_key.sign(&data);
                Ok(DataPayload::text(hex::encode(signature.to_bytes())))
            }
            "verify" => {
                let pub_hex = config
                    .get("public_key_hex")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        OmniError::Validation("Missing 'public_key_hex' in config".into())
                    })?;
                let sig_hex = config
                    .get("signature_hex")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        OmniError::Validation("Missing 'signature_hex' in config".into())
                    })?;

                let pub_bytes = hex::decode(pub_hex)
                    .map_err(|e| OmniError::InvalidInput(format!("Invalid public key hex: {e}")))?;
                let sig_bytes = hex::decode(sig_hex)
                    .map_err(|e| OmniError::InvalidInput(format!("Invalid signature hex: {e}")))?;

                if pub_bytes.len() != 32 || sig_bytes.len() != 64 {
                    return Err(OmniError::Validation(
                        "Invalid Ed25519 key or signature length".into(),
                    ));
                }
                let mut pk_arr = [0u8; 32];
                pk_arr.copy_from_slice(&pub_bytes);
                let verifying_key = VerifyingKey::from_bytes(&pk_arr)
                    .map_err(|e| OmniError::InvalidInput(format!("Invalid verifying key: {e}")))?;

                let mut sig_arr = [0u8; 64];
                sig_arr.copy_from_slice(&sig_bytes);
                let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);

                let data = input.into_bytes();
                let is_valid = verifying_key.verify(&data, &signature).is_ok();
                Ok(DataPayload::json(serde_json::json!({ "valid": is_valid })))
            }
            _ => Err(OmniError::Validation(format!(
                "Unknown action '{}'",
                action
            ))),
        }
    }
}
