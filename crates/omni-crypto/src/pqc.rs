use fips203::ml_kem_768;
use fips203::traits::{Decaps, Encaps, KeyGen as KemKeyGen, SerDes as KemSerDes};
use fips204::ml_dsa_65;
use fips204::traits::{SerDes as DsaSerDes, Signer as DsaSigner, Verifier as DsaVerifier};
use fips205::slh_dsa_sha2_128f;
use fips205::traits::{SerDes as SlhSerDes, Signer as SlhSigner, Verifier as SlhVerifier};
use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
};
use serde_json::{json, Value};

pub struct PqcOp {
    pub algorithm: String,
}

#[async_trait]
impl Operation for PqcOp {
    fn manifest(&self) -> OperationManifest {
        let alg_lower = self.algorithm.to_lowercase();
        let (status, desc, limitations) = match alg_lower.as_str() {
            "ml-kem" | "ml_kem" | "kyber" => (
                FeatureStatus::Verified,
                "NIST FIPS 203 ML-KEM-768 keygen, encapsulation, and decapsulation (pure Rust)".to_string(),
                vec!["Uses ML-KEM-768 (NIST Level 3) parameter set; secret keys are returned hex-encoded only when explicitly requested via action='keygen'".to_string()],
            ),
            "ml-dsa" | "ml_dsa" | "dilithium" => (
                FeatureStatus::Verified,
                "NIST FIPS 204 ML-DSA-65 keygen, signing, and verification (pure Rust)".to_string(),
                vec!["Uses ML-DSA-65 (NIST Level 3) parameter set with empty context string by default".to_string()],
            ),
            "sphincs_plus" | "sphincs" | "slh_dsa" => (
                FeatureStatus::Verified,
                "NIST FIPS 205 SLH-DSA-SHA2-128f stateless hash-based signatures (pure Rust)".to_string(),
                vec!["Uses SLH-DSA-SHA2-128f parameter set; signing is computationally heavier than lattice schemes".to_string()],
            ),
            "falcon" => (
                FeatureStatus::Unsupported,
                "FN-DSA (Falcon) — not yet finalized as a NIST FIPS standard; cryptographic operations are not implemented".to_string(),
                vec!["No audited pure-Rust NIST-finalized FN-DSA crate is bundled; operation returns unsupported error rather than simulating cryptography".to_string()],
            ),
            _ => (
                FeatureStatus::Unsupported,
                format!("Post-Quantum algorithm: {}", self.algorithm),
                vec!["Unsupported algorithm".to_string()],
            ),
        };

        OperationManifest::new(
            format!("crypto.pqc.{}", alg_lower.replace('-', "_")),
            format!("Post-Quantum ({})", self.algorithm.to_uppercase()),
            desc,
            OperationCategory::Cryptography,
        )
        .with_types(vec![DataType::Text, DataType::Bytes], vec![DataType::Json])
        .with_status(status)
        .with_limitations(limitations)
        .with_tags(vec!["pqc".into(), "cryptography".into(), alg_lower])
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
            .unwrap_or("roundtrip");
        let msg = input.into_bytes();

        match self.algorithm.to_lowercase().as_str() {
            "ml-kem" | "ml_kem" | "kyber" => execute_ml_kem(action, &config),
            "ml-dsa" | "ml_dsa" | "dilithium" => execute_ml_dsa(action, &msg, &config),
            "sphincs_plus" | "sphincs" | "slh_dsa" => execute_slh_dsa(action, &msg, &config),
            "falcon" => Err(OmniError::Validation(
                "FN-DSA (Falcon) cryptographic operations are unsupported in this release (standardization pending; use crypto.pqc.ml_dsa or crypto.pqc.sphincs_plus for NIST FIPS 204/205 signatures).".into(),
            )),
            _ => Err(OmniError::NotFound(format!(
                "PQC algorithm '{}' not recognized",
                self.algorithm
            ))),
        }
    }
}

fn execute_ml_kem(action: &str, config: &Value) -> OmniResult<DataPayload> {
    match action {
        "keygen" => {
            let (ek, dk) = ml_kem_768::KG::try_keygen().map_err(|e| OmniError::Execution {
                operation: "ml_kem_keygen".into(),
                message: e.to_string(),
            })?;
            let ek_bytes = ek.into_bytes();
            let dk_bytes = dk.into_bytes();
            Ok(DataPayload::json(json!({
                "standard": "FIPS 203 (ML-KEM-768)",
                "action": "keygen",
                "encapsulation_key_hex": hex::encode(ek_bytes),
                "decapsulation_key_hex": hex::encode(dk_bytes),
                "encapsulation_key_bytes": ek_bytes.len(),
                "decapsulation_key_bytes": dk_bytes.len(),
            })))
        }
        "encapsulate" => {
            let ek_hex = config
                .get("public_key_hex")
                .or_else(|| config.get("encapsulation_key_hex"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    OmniError::InvalidInput(
                        "Missing 'encapsulation_key_hex' (or 'public_key_hex') for ML-KEM encapsulate".into(),
                    )
                })?;
            let ek_raw = hex::decode(ek_hex.trim()).map_err(|e| {
                OmniError::InvalidInput(format!("Invalid encapsulation key hex: {e}"))
            })?;
            let ek_arr: [u8; ml_kem_768::EK_LEN] = ek_raw.try_into().map_err(|v: Vec<u8>| {
                OmniError::InvalidInput(format!(
                    "ML-KEM-768 encapsulation key must be {} bytes, got {}",
                    ml_kem_768::EK_LEN,
                    v.len()
                ))
            })?;
            let ek = ml_kem_768::EncapsKey::try_from_bytes(ek_arr).map_err(|e| {
                OmniError::InvalidInput(format!("Invalid ML-KEM-768 encapsulation key: {e}"))
            })?;
            let (ssk, ct) = ek.try_encaps().map_err(|e| OmniError::Execution {
                operation: "ml_kem_encaps".into(),
                message: e.to_string(),
            })?;
            Ok(DataPayload::json(json!({
                "standard": "FIPS 203 (ML-KEM-768)",
                "action": "encapsulate",
                "ciphertext_hex": hex::encode(ct.into_bytes()),
                "shared_secret_hex": hex::encode(ssk.into_bytes()),
                "ciphertext_bytes": ml_kem_768::CT_LEN,
                "shared_secret_bytes": 32,
            })))
        }
        "decapsulate" => {
            let dk_hex = config
                .get("secret_key_hex")
                .or_else(|| config.get("decapsulation_key_hex"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    OmniError::InvalidInput(
                        "Missing 'decapsulation_key_hex' (or 'secret_key_hex') for ML-KEM decapsulate".into(),
                    )
                })?;
            let ct_hex = config
                .get("ciphertext_hex")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    OmniError::InvalidInput(
                        "Missing 'ciphertext_hex' for ML-KEM decapsulate".into(),
                    )
                })?;
            let dk_raw = hex::decode(dk_hex.trim()).map_err(|e| {
                OmniError::InvalidInput(format!("Invalid decapsulation key hex: {e}"))
            })?;
            let ct_raw = hex::decode(ct_hex.trim())
                .map_err(|e| OmniError::InvalidInput(format!("Invalid ciphertext hex: {e}")))?;
            let dk_arr: [u8; ml_kem_768::DK_LEN] = dk_raw.try_into().map_err(|v: Vec<u8>| {
                OmniError::InvalidInput(format!(
                    "ML-KEM-768 decapsulation key must be {} bytes, got {}",
                    ml_kem_768::DK_LEN,
                    v.len()
                ))
            })?;
            let ct_arr: [u8; ml_kem_768::CT_LEN] = ct_raw.try_into().map_err(|v: Vec<u8>| {
                OmniError::InvalidInput(format!(
                    "ML-KEM-768 ciphertext must be {} bytes, got {}",
                    ml_kem_768::CT_LEN,
                    v.len()
                ))
            })?;
            let dk = ml_kem_768::DecapsKey::try_from_bytes(dk_arr).map_err(|e| {
                OmniError::InvalidInput(format!("Invalid ML-KEM-768 decapsulation key: {e}"))
            })?;
            let ct = ml_kem_768::CipherText::try_from_bytes(ct_arr).map_err(|e| {
                OmniError::InvalidInput(format!("Invalid ML-KEM-768 ciphertext: {e}"))
            })?;
            let ssk = dk.try_decaps(&ct).map_err(|e| OmniError::Execution {
                operation: "ml_kem_decaps".into(),
                message: e.to_string(),
            })?;
            Ok(DataPayload::json(json!({
                "standard": "FIPS 203 (ML-KEM-768)",
                "action": "decapsulate",
                "shared_secret_hex": hex::encode(ssk.into_bytes()),
                "shared_secret_bytes": 32,
            })))
        }
        "roundtrip" => {
            let (ek, dk) = ml_kem_768::KG::try_keygen().map_err(|e| OmniError::Execution {
                operation: "ml_kem_keygen".into(),
                message: e.to_string(),
            })?;
            let (ssk_enc, ct) = ek.try_encaps().map_err(|e| OmniError::Execution {
                operation: "ml_kem_encaps".into(),
                message: e.to_string(),
            })?;
            let ssk_dec = dk.try_decaps(&ct).map_err(|e| OmniError::Execution {
                operation: "ml_kem_decaps".into(),
                message: e.to_string(),
            })?;
            let enc_bytes = ssk_enc.into_bytes();
            let dec_bytes = ssk_dec.into_bytes();
            Ok(DataPayload::json(json!({
                "standard": "FIPS 203 (ML-KEM-768)",
                "action": "roundtrip",
                "shared_secrets_match": enc_bytes == dec_bytes,
                "encapsulation_key_bytes": ml_kem_768::EK_LEN,
                "ciphertext_bytes": ml_kem_768::CT_LEN,
                "shared_secret_bytes": enc_bytes.len(),
                "shared_secret_hex": hex::encode(enc_bytes),
            })))
        }
        other => Err(OmniError::InvalidInput(format!(
            "Unknown ML-KEM action '{}'. Supported: keygen, encapsulate, decapsulate, roundtrip",
            other
        ))),
    }
}

fn execute_ml_dsa(action: &str, msg: &[u8], config: &Value) -> OmniResult<DataPayload> {
    let context = config
        .get("context")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .as_bytes();

    match action {
        "keygen" => {
            let (pk, sk) = ml_dsa_65::try_keygen().map_err(|e| OmniError::Execution {
                operation: "ml_dsa_keygen".into(),
                message: e.to_string(),
            })?;
            let pk_bytes = pk.into_bytes();
            let sk_bytes = sk.into_bytes();
            Ok(DataPayload::json(json!({
                "standard": "FIPS 204 (ML-DSA-65)",
                "action": "keygen",
                "public_key_hex": hex::encode(pk_bytes),
                "secret_key_hex": hex::encode(sk_bytes),
                "public_key_bytes": pk_bytes.len(),
                "secret_key_bytes": sk_bytes.len(),
            })))
        }
        "sign" => {
            let sk_hex = config
                .get("secret_key_hex")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    OmniError::InvalidInput("Missing 'secret_key_hex' for ML-DSA sign".into())
                })?;
            let sk_raw = hex::decode(sk_hex.trim())
                .map_err(|e| OmniError::InvalidInput(format!("Invalid secret key hex: {e}")))?;
            let sk_arr: [u8; ml_dsa_65::SK_LEN] = sk_raw.try_into().map_err(|v: Vec<u8>| {
                OmniError::InvalidInput(format!(
                    "ML-DSA-65 secret key must be {} bytes, got {}",
                    ml_dsa_65::SK_LEN,
                    v.len()
                ))
            })?;
            let sk = ml_dsa_65::PrivateKey::try_from_bytes(sk_arr).map_err(|e| {
                OmniError::InvalidInput(format!("Invalid ML-DSA-65 secret key: {e}"))
            })?;
            let sig = sk
                .try_sign(msg, context)
                .map_err(|e| OmniError::Execution {
                    operation: "ml_dsa_sign".into(),
                    message: e.to_string(),
                })?;
            Ok(DataPayload::json(json!({
                "standard": "FIPS 204 (ML-DSA-65)",
                "action": "sign",
                "signature_hex": hex::encode(sig),
                "signature_bytes": sig.len(),
            })))
        }
        "verify" => {
            let pk_hex = config
                .get("public_key_hex")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    OmniError::InvalidInput("Missing 'public_key_hex' for ML-DSA verify".into())
                })?;
            let sig_hex = config
                .get("signature_hex")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    OmniError::InvalidInput("Missing 'signature_hex' for ML-DSA verify".into())
                })?;
            let pk_raw = hex::decode(pk_hex.trim())
                .map_err(|e| OmniError::InvalidInput(format!("Invalid public key hex: {e}")))?;
            let sig_raw = hex::decode(sig_hex.trim())
                .map_err(|e| OmniError::InvalidInput(format!("Invalid signature hex: {e}")))?;
            let pk_arr: [u8; ml_dsa_65::PK_LEN] = pk_raw.try_into().map_err(|v: Vec<u8>| {
                OmniError::InvalidInput(format!(
                    "ML-DSA-65 public key must be {} bytes, got {}",
                    ml_dsa_65::PK_LEN,
                    v.len()
                ))
            })?;
            let sig_arr: [u8; ml_dsa_65::SIG_LEN] = sig_raw.try_into().map_err(|v: Vec<u8>| {
                OmniError::InvalidInput(format!(
                    "ML-DSA-65 signature must be {} bytes, got {}",
                    ml_dsa_65::SIG_LEN,
                    v.len()
                ))
            })?;
            let pk = ml_dsa_65::PublicKey::try_from_bytes(pk_arr).map_err(|e| {
                OmniError::InvalidInput(format!("Invalid ML-DSA-65 public key: {e}"))
            })?;
            let valid = pk.verify(msg, &sig_arr, context);
            Ok(DataPayload::json(json!({
                "standard": "FIPS 204 (ML-DSA-65)",
                "action": "verify",
                "valid": valid,
            })))
        }
        "roundtrip" => {
            let (pk, sk) = ml_dsa_65::try_keygen().map_err(|e| OmniError::Execution {
                operation: "ml_dsa_keygen".into(),
                message: e.to_string(),
            })?;
            let sig = sk
                .try_sign(msg, context)
                .map_err(|e| OmniError::Execution {
                    operation: "ml_dsa_sign".into(),
                    message: e.to_string(),
                })?;
            let valid = pk.verify(msg, &sig, context);
            Ok(DataPayload::json(json!({
                "standard": "FIPS 204 (ML-DSA-65)",
                "action": "roundtrip",
                "valid": valid,
                "public_key_bytes": ml_dsa_65::PK_LEN,
                "signature_bytes": sig.len(),
                "message_bytes": msg.len(),
            })))
        }
        other => Err(OmniError::InvalidInput(format!(
            "Unknown ML-DSA action '{}'. Supported: keygen, sign, verify, roundtrip",
            other
        ))),
    }
}

fn execute_slh_dsa(action: &str, msg: &[u8], config: &Value) -> OmniResult<DataPayload> {
    let context = config
        .get("context")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .as_bytes();

    match action {
        "keygen" => {
            let (pk, sk) = slh_dsa_sha2_128f::try_keygen().map_err(|e| OmniError::Execution {
                operation: "slh_dsa_keygen".into(),
                message: e.to_string(),
            })?;
            let pk_bytes = pk.into_bytes();
            let sk_bytes = sk.into_bytes();
            Ok(DataPayload::json(json!({
                "standard": "FIPS 205 (SLH-DSA-SHA2-128f)",
                "action": "keygen",
                "public_key_hex": hex::encode(pk_bytes),
                "secret_key_hex": hex::encode(sk_bytes),
                "public_key_bytes": pk_bytes.len(),
                "secret_key_bytes": sk_bytes.len(),
            })))
        }
        "sign" => {
            let sk_hex = config
                .get("secret_key_hex")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    OmniError::InvalidInput("Missing 'secret_key_hex' for SLH-DSA sign".into())
                })?;
            let sk_raw = hex::decode(sk_hex.trim())
                .map_err(|e| OmniError::InvalidInput(format!("Invalid secret key hex: {e}")))?;
            let sk_arr: [u8; slh_dsa_sha2_128f::SK_LEN] =
                sk_raw.try_into().map_err(|v: Vec<u8>| {
                    OmniError::InvalidInput(format!(
                        "SLH-DSA-SHA2-128f secret key must be {} bytes, got {}",
                        slh_dsa_sha2_128f::SK_LEN,
                        v.len()
                    ))
                })?;
            let sk = slh_dsa_sha2_128f::PrivateKey::try_from_bytes(sk_arr)
                .map_err(|e| OmniError::InvalidInput(format!("Invalid SLH-DSA secret key: {e}")))?;
            let sig = sk
                .try_sign(msg, context, false)
                .map_err(|e| OmniError::Execution {
                    operation: "slh_dsa_sign".into(),
                    message: e.to_string(),
                })?;
            Ok(DataPayload::json(json!({
                "standard": "FIPS 205 (SLH-DSA-SHA2-128f)",
                "action": "sign",
                "signature_hex": hex::encode(sig),
                "signature_bytes": sig.len(),
            })))
        }
        "verify" => {
            let pk_hex = config
                .get("public_key_hex")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    OmniError::InvalidInput("Missing 'public_key_hex' for SLH-DSA verify".into())
                })?;
            let sig_hex = config
                .get("signature_hex")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    OmniError::InvalidInput("Missing 'signature_hex' for SLH-DSA verify".into())
                })?;
            let pk_raw = hex::decode(pk_hex.trim())
                .map_err(|e| OmniError::InvalidInput(format!("Invalid public key hex: {e}")))?;
            let sig_raw = hex::decode(sig_hex.trim())
                .map_err(|e| OmniError::InvalidInput(format!("Invalid signature hex: {e}")))?;
            let pk_arr: [u8; slh_dsa_sha2_128f::PK_LEN] =
                pk_raw.try_into().map_err(|v: Vec<u8>| {
                    OmniError::InvalidInput(format!(
                        "SLH-DSA-SHA2-128f public key must be {} bytes, got {}",
                        slh_dsa_sha2_128f::PK_LEN,
                        v.len()
                    ))
                })?;
            let sig_arr: [u8; slh_dsa_sha2_128f::SIG_LEN] =
                sig_raw.try_into().map_err(|v: Vec<u8>| {
                    OmniError::InvalidInput(format!(
                        "SLH-DSA-SHA2-128f signature must be {} bytes, got {}",
                        slh_dsa_sha2_128f::SIG_LEN,
                        v.len()
                    ))
                })?;
            let pk = slh_dsa_sha2_128f::PublicKey::try_from_bytes(pk_arr)
                .map_err(|e| OmniError::InvalidInput(format!("Invalid SLH-DSA public key: {e}")))?;
            let valid = pk.verify(msg, &sig_arr, context);
            Ok(DataPayload::json(json!({
                "standard": "FIPS 205 (SLH-DSA-SHA2-128f)",
                "action": "verify",
                "valid": valid,
            })))
        }
        "roundtrip" => {
            let (pk, sk) = slh_dsa_sha2_128f::try_keygen().map_err(|e| OmniError::Execution {
                operation: "slh_dsa_keygen".into(),
                message: e.to_string(),
            })?;
            let sig = sk
                .try_sign(msg, context, false)
                .map_err(|e| OmniError::Execution {
                    operation: "slh_dsa_sign".into(),
                    message: e.to_string(),
                })?;
            let valid = pk.verify(msg, &sig, context);
            Ok(DataPayload::json(json!({
                "standard": "FIPS 205 (SLH-DSA-SHA2-128f)",
                "action": "roundtrip",
                "valid": valid,
                "public_key_bytes": slh_dsa_sha2_128f::PK_LEN,
                "signature_bytes": sig.len(),
                "message_bytes": msg.len(),
            })))
        }
        other => Err(OmniError::InvalidInput(format!(
            "Unknown SLH-DSA action '{}'. Supported: keygen, sign, verify, roundtrip",
            other
        ))),
    }
}
