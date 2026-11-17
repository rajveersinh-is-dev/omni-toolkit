use blake2::{Blake2b512, Blake2s256};
use md5::Md5;
use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use ripemd::Ripemd160;
use serde_json::Value;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use sha3::{digest::Update, Sha3_224, Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256};

pub struct GenericHashOp {
    pub algorithm: String,
}

#[async_trait]
impl Operation for GenericHashOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            format!("crypto.hash.{}", self.algorithm.to_lowercase().replace('/', "_")),
            format!("Hash ({})", self.algorithm.to_uppercase()),
            format!("Computes cryptographic hash using {}", self.algorithm),
            OperationCategory::Cryptography,
        )
        .with_types(vec![DataType::Bytes, DataType::Text], vec![DataType::Text])
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let bytes = input.into_bytes();
        let digest_hex = match self.algorithm.to_lowercase().as_str() {
            // Legacy
            "md5" => hex::encode(Md5::digest(&bytes)),
            "sha1" => {
                let mut hasher = sha1::Sha1::new();
                Digest::update(&mut hasher, &bytes);
                hex::encode(hasher.finalize())
            }
            "ripemd160" => hex::encode(Ripemd160::digest(&bytes)),

            // SHA-2
            "sha224" => hex::encode(Sha224::digest(&bytes)),
            "sha256" => hex::encode(Sha256::digest(&bytes)),
            "sha384" => hex::encode(Sha384::digest(&bytes)),
            "sha512" => hex::encode(Sha512::digest(&bytes)),
            "sha512_224" => hex::encode(Sha512_224::digest(&bytes)),
            "sha512_256" => hex::encode(Sha512_256::digest(&bytes)),

            // SHA-3
            "sha3_224" => hex::encode(Sha3_224::digest(&bytes)),
            "sha3_256" => hex::encode(Sha3_256::digest(&bytes)),
            "sha3_384" => hex::encode(Sha3_384::digest(&bytes)),
            "sha3_512" => hex::encode(Sha3_512::digest(&bytes)),
            "shake128" => {
                use sha3::digest::ExtendableOutput;
                use sha3::digest::XofReader;
                let mut hasher = Shake128::default();
                hasher.update(&bytes);
                let mut reader = hasher.finalize_xof();
                let len = config.get("length").and_then(|v| v.as_u64()).unwrap_or(32) as usize;
                let mut out = vec![0u8; len];
                reader.read(&mut out);
                hex::encode(out)
            }
            "shake256" => {
                use sha3::digest::ExtendableOutput;
                use sha3::digest::XofReader;
                let mut hasher = Shake256::default();
                hasher.update(&bytes);
                let mut reader = hasher.finalize_xof();
                let len = config.get("length").and_then(|v| v.as_u64()).unwrap_or(64) as usize;
                let mut out = vec![0u8; len];
                reader.read(&mut out);
                hex::encode(out)
            }

            // High Performance
            "blake2s" => hex::encode(Blake2s256::digest(&bytes)),
            "blake2b" => hex::encode(Blake2b512::digest(&bytes)),
            "blake3" => {
                let hash = blake3::hash(&bytes);
                hash.to_hex().to_string()
            }
            "xxhash32" => {
                use std::hash::Hasher;
                let mut hasher = twox_hash::XxHash32::default();
                hasher.write(&bytes);
                format!("{:08x}", hasher.finish())
            }
            "xxhash64" => {
                use std::hash::Hasher;
                let mut hasher = twox_hash::XxHash64::default();
                hasher.write(&bytes);
                format!("{:016x}", hasher.finish())
            }
            "murmur3" => {
                let mut cursor = std::io::Cursor::new(&bytes);
                let hash = murmur3::murmur3_32(&mut cursor, 0).unwrap_or(0);
                format!("{:08x}", hash)
            }

            _ => hex::encode(Sha256::digest(&bytes)),
        };

        Ok(DataPayload::text(digest_hex))
    }
}
