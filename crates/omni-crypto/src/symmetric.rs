use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Aes256Gcm, Nonce,
};
use chacha20poly1305::ChaCha20Poly1305;
use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
};

use serde_json::Value;

pub struct SymmetricOp {
    pub cipher: String,
}

#[async_trait]
impl Operation for SymmetricOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            format!(
                "crypto.symmetric.{}",
                self.cipher.to_lowercase().replace('-', "_")
            ),
            format!("Symmetric Cipher ({})", self.cipher.to_uppercase()),
            format!("Symmetric encryption and decryption using {}", self.cipher),
            OperationCategory::Cryptography,
        )
        .with_types(
            vec![DataType::Bytes, DataType::Text],
            vec![DataType::Bytes, DataType::Text],
        )
        .with_status(FeatureStatus::Verified)
        .with_tags(vec![
            "crypto".into(),
            "symmetric".into(),
            self.cipher.to_lowercase(),
        ])
    }

    async fn execute(
        &self,
        input: DataPayload,
        config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let decode = config
            .get("decode")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let key_str = config
            .get("key")
            .and_then(|v| v.as_str())
            .unwrap_or("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let key_bytes = hex::decode(key_str).unwrap_or_else(|_| key_str.as_bytes().to_vec());
        let iv_str = config
            .get("iv")
            .and_then(|v| v.as_str())
            .unwrap_or("000102030405060708090a0b");
        let iv_bytes = hex::decode(iv_str).unwrap_or_else(|_| iv_str.as_bytes().to_vec());

        let payload_bytes = input.into_bytes();

        match self.cipher.to_lowercase().as_str() {
            "aes-256-gcm" | "aes_gcm" => {
                if key_bytes.len() < 32 {
                    return Err(OmniError::Validation(
                        "AES-256-GCM requires at least a 32-byte key".into(),
                    ));
                }
                if iv_bytes.len() < 12 {
                    return Err(OmniError::Validation(
                        "AES-256-GCM requires a 12-byte (96-bit) IV/nonce".into(),
                    ));
                }
                let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes[..32]);
                let cipher = Aes256Gcm::new(key);
                let nonce = Nonce::from_slice(&iv_bytes[..12]);

                if decode {
                    let decrypted = cipher.decrypt(nonce, payload_bytes.as_ref()).map_err(|e| {
                        OmniError::Execution {
                            operation: "aes-256-gcm".into(),
                            message: e.to_string(),
                        }
                    })?;
                    Ok(DataPayload::bytes(decrypted))
                } else {
                    let encrypted = cipher.encrypt(nonce, payload_bytes.as_ref()).map_err(|e| {
                        OmniError::Execution {
                            operation: "aes-256-gcm".into(),
                            message: e.to_string(),
                        }
                    })?;
                    Ok(DataPayload::bytes(encrypted))
                }
            }
            "aes-128-gcm" => {
                if key_bytes.len() < 16 {
                    return Err(OmniError::Validation(
                        "AES-128-GCM requires at least a 16-byte key".into(),
                    ));
                }
                if iv_bytes.len() < 12 {
                    return Err(OmniError::Validation(
                        "AES-128-GCM requires a 12-byte (96-bit) IV/nonce".into(),
                    ));
                }
                let key = aes_gcm::Key::<Aes128Gcm>::from_slice(&key_bytes[..16]);
                let cipher = Aes128Gcm::new(key);
                let nonce = Nonce::from_slice(&iv_bytes[..12]);

                if decode {
                    let decrypted = cipher.decrypt(nonce, payload_bytes.as_ref()).map_err(|e| {
                        OmniError::Execution {
                            operation: "aes-128-gcm".into(),
                            message: e.to_string(),
                        }
                    })?;
                    Ok(DataPayload::bytes(decrypted))
                } else {
                    let encrypted = cipher.encrypt(nonce, payload_bytes.as_ref()).map_err(|e| {
                        OmniError::Execution {
                            operation: "aes-128-gcm".into(),
                            message: e.to_string(),
                        }
                    })?;
                    Ok(DataPayload::bytes(encrypted))
                }
            }
            "chacha20poly1305" | "chacha20-poly1305" => {
                if key_bytes.len() < 32 {
                    return Err(OmniError::Validation(
                        "ChaCha20-Poly1305 requires at least a 32-byte key".into(),
                    ));
                }
                if iv_bytes.len() < 12 {
                    return Err(OmniError::Validation(
                        "ChaCha20-Poly1305 requires a 12-byte (96-bit) IV/nonce".into(),
                    ));
                }
                let key = chacha20poly1305::Key::from_slice(&key_bytes[..32]);
                let cipher = ChaCha20Poly1305::new(key);
                let nonce = chacha20poly1305::Nonce::from_slice(&iv_bytes[..12]);

                if decode {
                    let decrypted = cipher.decrypt(nonce, payload_bytes.as_ref()).map_err(|e| {
                        OmniError::Execution {
                            operation: "chacha20-poly1305".into(),
                            message: e.to_string(),
                        }
                    })?;
                    Ok(DataPayload::bytes(decrypted))
                } else {
                    let encrypted = cipher.encrypt(nonce, payload_bytes.as_ref()).map_err(|e| {
                        OmniError::Execution {
                            operation: "chacha20-poly1305".into(),
                            message: e.to_string(),
                        }
                    })?;
                    Ok(DataPayload::bytes(encrypted))
                }
            }
            "rc4" => {
                if key_bytes.is_empty() {
                    return Err(OmniError::Validation("RC4 key cannot be empty".into()));
                }
                let mut s = [0u8; 256];
                for (idx, slot) in s.iter_mut().enumerate() {
                    *slot = idx as u8;
                }
                let mut j: usize = 0;
                for i in 0..256 {
                    j = (j + s[i] as usize + key_bytes[i % key_bytes.len()] as usize) % 256;
                    s.swap(i, j);
                }

                let mut buffer = payload_bytes;
                let mut i: usize = 0;
                let mut j: usize = 0;
                for byte in buffer.iter_mut() {
                    i = (i + 1) % 256;
                    j = (j + s[i] as usize) % 256;
                    s.swap(i, j);
                    let k = s[(s[i] as usize + s[j] as usize) % 256];
                    *byte ^= k;
                }
                Ok(DataPayload::bytes(buffer))
            }
            _ => Err(OmniError::NotFound(format!(
                "Cipher {} not supported",
                self.cipher
            ))),
        }
    }
}
