use argon2::{Algorithm, Argon2, Params, Version};
use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
};
use serde_json::Value;

pub struct KdfOp {
    pub algorithm: String,
}

#[async_trait]
impl Operation for KdfOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            format!("kdf.{}", self.algorithm.to_lowercase()),
            format!("Password Hash / KDF ({})", self.algorithm.to_uppercase()),
            format!(
                "Password hashing and key derivation using {}",
                self.algorithm
            ),
            OperationCategory::Cryptography,
        )
        .with_types(vec![DataType::Text, DataType::Bytes], vec![DataType::Text])
        .with_status(FeatureStatus::Verified)
        .with_tags(vec![
            "crypto".into(),
            "kdf".into(),
            self.algorithm.to_lowercase(),
        ])
    }

    async fn execute(
        &self,
        input: DataPayload,
        config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let password = input.into_text()?;
        let salt = config
            .get("salt")
            .and_then(|v| v.as_str())
            .unwrap_or("somesalt12345678");

        match self.algorithm.to_lowercase().as_str() {
            "argon2id" | "argon2i" | "argon2d" => {
                let alg = match self.algorithm.to_lowercase().as_str() {
                    "argon2d" => Algorithm::Argon2d,
                    "argon2i" => Algorithm::Argon2i,
                    _ => Algorithm::Argon2id,
                };
                let params = Params::default();
                let argon = Argon2::new(alg, Version::V0x13, params);
                let mut hash_key = [0u8; 32];
                argon
                    .hash_password_into(password.as_bytes(), salt.as_bytes(), &mut hash_key)
                    .map_err(|e| OmniError::Execution {
                        operation: self.algorithm.clone(),
                        message: e.to_string(),
                    })?;
                Ok(DataPayload::text(hex::encode(hash_key)))
            }
            "bcrypt" => {
                let cost_u64 = config.get("cost").and_then(|v| v.as_u64()).unwrap_or(10);
                if !(4..=16).contains(&cost_u64) {
                    return Err(OmniError::Validation(
                        "bcrypt cost must be between 4 and 16".into(),
                    ));
                }
                let hashed =
                    bcrypt::hash(&password, cost_u64 as u32).map_err(|e| OmniError::Execution {
                        operation: "bcrypt".into(),
                        message: e.to_string(),
                    })?;
                Ok(DataPayload::text(hashed))
            }
            "scrypt" => {
                let params =
                    scrypt::Params::new(14, 8, 1, 32).map_err(|e| OmniError::Execution {
                        operation: "scrypt".into(),
                        message: e.to_string(),
                    })?;
                let mut output = [0u8; 32];
                scrypt::scrypt(password.as_bytes(), salt.as_bytes(), &params, &mut output)
                    .map_err(|e| OmniError::Execution {
                        operation: "scrypt".into(),
                        message: e.to_string(),
                    })?;
                Ok(DataPayload::text(hex::encode(output)))
            }
            "pbkdf2" => {
                let rounds_u64 = config
                    .get("rounds")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(100_000);
                if !(1..=10_000_000).contains(&rounds_u64) {
                    return Err(OmniError::Validation(
                        "PBKDF2 rounds must be between 1 and 10,000,000".into(),
                    ));
                }
                let mut key = [0u8; 32];
                pbkdf2::pbkdf2_hmac::<sha2::Sha256>(
                    password.as_bytes(),
                    salt.as_bytes(),
                    rounds_u64 as u32,
                    &mut key,
                );
                Ok(DataPayload::text(hex::encode(key)))
            }
            "hkdf" => {
                use hkdf::Hkdf;
                use sha2::Sha256;
                let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), password.as_bytes());
                let mut okm = [0u8; 32];
                let info = config
                    .get("info")
                    .and_then(|v| v.as_str())
                    .unwrap_or("omni-key");
                hk.expand(info.as_bytes(), &mut okm)
                    .map_err(|e| OmniError::Execution {
                        operation: "hkdf".into(),
                        message: e.to_string(),
                    })?;
                Ok(DataPayload::text(hex::encode(okm)))
            }
            _ => Err(OmniError::NotFound(format!(
                "KDF algorithm {} not supported",
                self.algorithm
            ))),
        }
    }
}
