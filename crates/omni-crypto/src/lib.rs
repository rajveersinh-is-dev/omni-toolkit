pub mod asymmetric;
pub mod checksum;
pub mod classical;
pub mod entropy;
pub mod hash;
pub mod jwt;
pub mod kdf;
pub mod pki;
pub mod pqc;
pub mod signatures;
pub mod symmetric;

pub use asymmetric::*;
pub use checksum::*;
pub use classical::*;
pub use entropy::*;
pub use hash::*;
pub use jwt::*;
pub use kdf::*;
pub use pki::*;
pub use pqc::*;
pub use signatures::*;
pub use symmetric::*;

use omni_core::OmniResult;
use omni_registry::OperationRegistry;
use std::sync::Arc;

pub fn register_crypto(registry: &mut OperationRegistry) -> OmniResult<()> {
    // Classical
    registry.register(Arc::new(RotOp { variant: "5".into() }))?;
    registry.register(Arc::new(RotOp { variant: "13".into() }))?;
    registry.register(Arc::new(RotOp { variant: "18".into() }))?;
    registry.register(Arc::new(RotOp { variant: "47".into() }))?;
    registry.register(Arc::new(AtbashOp))?;
    registry.register(Arc::new(AffineOp))?;
    registry.register(Arc::new(VigenereOp))?;
    registry.register(Arc::new(MorseOp))?;
    registry.register(Arc::new(EnigmaOp))?;

    // Hashing
    let hash_algs = [
        "md5", "sha1", "ripemd160", "sha224", "sha256", "sha384", "sha512",
        "sha512_224", "sha512_256", "sha3_224", "sha3_256", "sha3_384", "sha3_512",
        "shake128", "shake256", "blake2s", "blake2b", "blake3", "xxhash32", "xxhash64", "murmur3",
    ];
    for alg in hash_algs {
        registry.register(Arc::new(GenericHashOp { algorithm: alg.into() }))?;
    }

    // Checksums
    let checksum_algs = ["crc8", "crc16", "crc32", "crc32_castagnoli", "crc64", "adler32", "fletcher16", "fletcher32"];
    for alg in checksum_algs {
        registry.register(Arc::new(ChecksumOp { algorithm: alg.into() }))?;
    }

    // KDF
    let kdf_algs = ["argon2id", "argon2i", "argon2d", "bcrypt", "scrypt", "pbkdf2", "hkdf"];
    for alg in kdf_algs {
        registry.register(Arc::new(KdfOp { algorithm: alg.into() }))?;
    }

    // Symmetric
    let symmetric_ciphers = ["aes-256-gcm", "aes-128-gcm", "chacha20poly1305", "rc4"];
    for c in symmetric_ciphers {
        registry.register(Arc::new(SymmetricOp { cipher: c.into() }))?;
    }

    // Asymmetric, PKI, JWT, Auth, Entropy, PQC
    registry.register(Arc::new(RsaOp))?;
    registry.register(Arc::new(Ed25519Op))?;
    registry.register(Arc::new(X509InspectOp))?;
    registry.register(Arc::new(JwtDebuggerOp))?;
    registry.register(Arc::new(SignaturesOp))?;
    registry.register(Arc::new(ShannonEntropyOp))?;
    registry.register(Arc::new(LsbSteganographyOp))?;
    registry.register(Arc::new(PqcOp { algorithm: "ml-kem".into() }))?;
    registry.register(Arc::new(PqcOp { algorithm: "ml-dsa".into() }))?;
    registry.register(Arc::new(PqcOp { algorithm: "sphincs_plus".into() }))?;
    registry.register(Arc::new(PqcOp { algorithm: "falcon".into() }))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use omni_core::{DataPayload, ExecutionContext, Operation};

    #[tokio::test]
    async fn test_sha256_and_blake3_hash() {
        let sha_op = GenericHashOp { algorithm: "sha256".into() };
        let blake_op = GenericHashOp { algorithm: "blake3".into() };
        let ctx = ExecutionContext::new("t_hash");

        let input = DataPayload::text("hello world");
        let sha_res = sha_op.execute(input.clone(), serde_json::json!({}), &ctx).await.unwrap();
        // Standard SHA-256 for "hello world"
        assert_eq!(sha_res.as_str().unwrap(), "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");

        let blake_res = blake_op.execute(input, serde_json::json!({}), &ctx).await.unwrap();
        // Standard BLAKE3 for "hello world"
        assert_eq!(blake_res.as_str().unwrap(), "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24");
    }

    #[tokio::test]
    async fn test_crc32_and_adler32() {
        let crc_op = ChecksumOp { algorithm: "crc32".into() };
        let adler_op = ChecksumOp { algorithm: "adler32".into() };
        let ctx = ExecutionContext::new("t_chk");

        let input = DataPayload::text("123456789");
        let crc_res = crc_op.execute(input.clone(), serde_json::json!({}), &ctx).await.unwrap();
        // CRC-32 for "123456789" is cbf43926
        assert_eq!(crc_res.as_str().unwrap(), "cbf43926");

        let adler_res = adler_op.execute(input, serde_json::json!({}), &ctx).await.unwrap();
        // Adler-32 for "123456789" is 091e01de
        assert_eq!(adler_res.as_str().unwrap(), "091e01de");
    }

    #[tokio::test]
    async fn test_rot13_and_atbash() {
        let rot_op = RotOp { variant: "13".into() };
        let atbash_op = AtbashOp;
        let ctx = ExecutionContext::new("t_rot");

        let input = DataPayload::text("Hello, World!");
        let rot = rot_op.execute(input, serde_json::json!({}), &ctx).await.unwrap();
        assert_eq!(rot.as_str().unwrap(), "Uryyb, Jbeyq!");

        let atbash_input = DataPayload::text("AZaz");
        let atbash_out = atbash_op.execute(atbash_input, serde_json::json!({}), &ctx).await.unwrap();
        assert_eq!(atbash_out.as_str().unwrap(), "ZAza");
    }

    #[tokio::test]
    async fn test_aes_gcm_roundtrip() {
        let op = SymmetricOp { cipher: "aes-256-gcm".into() };
        let ctx = ExecutionContext::new("t_aes");

        let plaintext = DataPayload::text("Confidential forensic artifact");
        let cfg_enc = serde_json::json!({ "decode": false });
        let encrypted = op.execute(plaintext, cfg_enc, &ctx).await.unwrap();

        let cfg_dec = serde_json::json!({ "decode": true });
        let decrypted = op.execute(encrypted, cfg_dec, &ctx).await.unwrap();
        assert_eq!(decrypted.into_text().unwrap(), "Confidential forensic artifact");
    }

    #[tokio::test]
    async fn test_shannon_entropy() {
        let op = ShannonEntropyOp;
        let ctx = ExecutionContext::new("t_ent");

        // Uniform 256 bytes should have 8.0 bits entropy
        let all_bytes: Vec<u8> = (0..=255).collect();
        let payload = DataPayload::bytes(all_bytes);
        let res = op.execute(payload, serde_json::json!({}), &ctx).await.unwrap();
        let json = res.into_json().unwrap();
        assert_eq!(json["entropy_bits_per_byte"], 8.0);
    }

    #[tokio::test]
    async fn test_lsb_steganography_roundtrip() {
        let op = LsbSteganographyOp;
        let ctx = ExecutionContext::new("t_stego");

        // Carrier of 1000 zero bytes
        let carrier = DataPayload::bytes(vec![0xAA; 1000]);
        let cfg_inject = serde_json::json!({
            "action": "inject",
            "secret": "HIDDEN_SECRET_KEY_42"
        });
        let stego_carrier = op.execute(carrier, cfg_inject, &ctx).await.unwrap();

        let cfg_extract = serde_json::json!({
            "action": "extract"
        });
        let extracted = op.execute(stego_carrier, cfg_extract, &ctx).await.unwrap();
        assert_eq!(extracted.as_str().unwrap(), "HIDDEN_SECRET_KEY_42");
    }
}
