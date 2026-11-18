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
    registry.register(Arc::new(RotOp {
        variant: "5".into(),
    }))?;
    registry.register(Arc::new(RotOp {
        variant: "13".into(),
    }))?;
    registry.register(Arc::new(RotOp {
        variant: "18".into(),
    }))?;
    registry.register(Arc::new(RotOp {
        variant: "47".into(),
    }))?;
    registry.register(Arc::new(AtbashOp))?;
    registry.register(Arc::new(AffineOp))?;
    registry.register(Arc::new(VigenereOp))?;
    registry.register(Arc::new(MorseOp))?;
    registry.register(Arc::new(EnigmaOp))?;

    // Hashing
    let hash_algs = [
        "md5",
        "sha1",
        "ripemd160",
        "sha224",
        "sha256",
        "sha384",
        "sha512",
        "sha512_224",
        "sha512_256",
        "sha3_224",
        "sha3_256",
        "sha3_384",
        "sha3_512",
        "shake128",
        "shake256",
        "blake2s",
        "blake2b",
        "blake3",
        "xxhash32",
        "xxhash64",
        "murmur3",
    ];
    for alg in hash_algs {
        registry.register(Arc::new(GenericHashOp {
            algorithm: alg.into(),
        }))?;
    }

    // Checksums
    let checksum_algs = [
        "crc8",
        "crc16",
        "crc32",
        "crc32_castagnoli",
        "crc64",
        "adler32",
        "fletcher16",
        "fletcher32",
    ];
    for alg in checksum_algs {
        registry.register(Arc::new(ChecksumOp {
            algorithm: alg.into(),
        }))?;
    }

    // KDF
    let kdf_algs = [
        "argon2id", "argon2i", "argon2d", "bcrypt", "scrypt", "pbkdf2", "hkdf",
    ];
    for alg in kdf_algs {
        registry.register(Arc::new(KdfOp {
            algorithm: alg.into(),
        }))?;
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
    registry.register(Arc::new(PqcOp {
        algorithm: "ml-kem".into(),
    }))?;
    registry.register(Arc::new(PqcOp {
        algorithm: "ml-dsa".into(),
    }))?;
    registry.register(Arc::new(PqcOp {
        algorithm: "sphincs_plus".into(),
    }))?;
    registry.register(Arc::new(PqcOp {
        algorithm: "falcon".into(),
    }))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use omni_core::{DataPayload, ExecutionContext, Operation};

    #[tokio::test]
    async fn test_sha256_and_blake3_hash() {
        let sha_op = GenericHashOp {
            algorithm: "sha256".into(),
        };
        let blake_op = GenericHashOp {
            algorithm: "blake3".into(),
        };
        let ctx = ExecutionContext::new("t_hash");

        let input = DataPayload::text("hello world");
        let sha_res = sha_op
            .execute(input.clone(), serde_json::json!({}), &ctx)
            .await
            .unwrap();
        // Standard SHA-256 for "hello world"
        assert_eq!(
            sha_res.as_str().unwrap(),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );

        let blake_res = blake_op
            .execute(input, serde_json::json!({}), &ctx)
            .await
            .unwrap();
        // Standard BLAKE3 for "hello world"
        assert_eq!(
            blake_res.as_str().unwrap(),
            "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24"
        );
    }

    #[tokio::test]
    async fn test_crc32_and_adler32() {
        let crc_op = ChecksumOp {
            algorithm: "crc32".into(),
        };
        let adler_op = ChecksumOp {
            algorithm: "adler32".into(),
        };
        let ctx = ExecutionContext::new("t_chk");

        let input = DataPayload::text("123456789");
        let crc_res = crc_op
            .execute(input.clone(), serde_json::json!({}), &ctx)
            .await
            .unwrap();
        // CRC-32 for "123456789" is cbf43926
        assert_eq!(crc_res.as_str().unwrap(), "cbf43926");

        let adler_res = adler_op
            .execute(input, serde_json::json!({}), &ctx)
            .await
            .unwrap();
        // Adler-32 for "123456789" is 091e01de
        assert_eq!(adler_res.as_str().unwrap(), "091e01de");
    }

    #[tokio::test]
    async fn test_rot13_and_atbash() {
        let rot_op = RotOp {
            variant: "13".into(),
        };
        let atbash_op = AtbashOp;
        let ctx = ExecutionContext::new("t_rot");

        let input = DataPayload::text("Hello, World!");
        let rot = rot_op
            .execute(input, serde_json::json!({}), &ctx)
            .await
            .unwrap();
        assert_eq!(rot.as_str().unwrap(), "Uryyb, Jbeyq!");

        let atbash_input = DataPayload::text("AZaz");
        let atbash_out = atbash_op
            .execute(atbash_input, serde_json::json!({}), &ctx)
            .await
            .unwrap();
        assert_eq!(atbash_out.as_str().unwrap(), "ZAza");
    }

    #[tokio::test]
    async fn test_aes_gcm_roundtrip() {
        let op = SymmetricOp {
            cipher: "aes-256-gcm".into(),
        };
        let ctx = ExecutionContext::new("t_aes");

        let plaintext = DataPayload::text("Confidential forensic artifact");
        let cfg_enc = serde_json::json!({ "decode": false });
        let encrypted = op.execute(plaintext, cfg_enc, &ctx).await.unwrap();

        let cfg_dec = serde_json::json!({ "decode": true });
        let decrypted = op.execute(encrypted, cfg_dec, &ctx).await.unwrap();
        assert_eq!(
            decrypted.into_text().unwrap(),
            "Confidential forensic artifact"
        );
    }

    #[tokio::test]
    async fn test_shannon_entropy() {
        let op = ShannonEntropyOp;
        let ctx = ExecutionContext::new("t_ent");

        // Uniform 256 bytes should have 8.0 bits entropy
        let all_bytes: Vec<u8> = (0..=255).collect();
        let payload = DataPayload::bytes(all_bytes);
        let res = op
            .execute(payload, serde_json::json!({}), &ctx)
            .await
            .unwrap();
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

    #[tokio::test]
    async fn test_pqc_ml_kem_768_real_keygen_encaps_decaps() {
        let op = PqcOp {
            algorithm: "ml-kem".into(),
        };
        let ctx = ExecutionContext::new("t_pqc_kem");

        let kp = op
            .execute(
                DataPayload::text(""),
                serde_json::json!({ "action": "keygen" }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        let ek_hex = kp["encapsulation_key_hex"].as_str().unwrap();
        let dk_hex = kp["decapsulation_key_hex"].as_str().unwrap();

        let enc = op
            .execute(
                DataPayload::text(""),
                serde_json::json!({ "action": "encapsulate", "encapsulation_key_hex": ek_hex }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        let ct_hex = enc["ciphertext_hex"].as_str().unwrap();
        let ss1 = enc["shared_secret_hex"].as_str().unwrap();

        let dec = op
            .execute(
                DataPayload::text(""),
                serde_json::json!({
                    "action": "decapsulate",
                    "decapsulation_key_hex": dk_hex,
                    "ciphertext_hex": ct_hex
                }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        let ss2 = dec["shared_secret_hex"].as_str().unwrap();
        assert_eq!(ss1, ss2);
        assert_eq!(ss1.len(), 64); // 32 bytes hex
    }

    #[tokio::test]
    async fn test_pqc_ml_dsa_65_sign_verify_and_tamper_detection() {
        let op = PqcOp {
            algorithm: "ml-dsa".into(),
        };
        let ctx = ExecutionContext::new("t_pqc_dsa");

        let kp = op
            .execute(
                DataPayload::text(""),
                serde_json::json!({ "action": "keygen" }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        let pk_hex = kp["public_key_hex"].as_str().unwrap();
        let sk_hex = kp["secret_key_hex"].as_str().unwrap();

        let signed = op
            .execute(
                DataPayload::text("authentic message"),
                serde_json::json!({ "action": "sign", "secret_key_hex": sk_hex }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        let sig_hex = signed["signature_hex"].as_str().unwrap();

        let verified = op
            .execute(
                DataPayload::text("authentic message"),
                serde_json::json!({
                    "action": "verify",
                    "public_key_hex": pk_hex,
                    "signature_hex": sig_hex
                }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(verified["valid"], true);

        // Tampered message must fail verification!
        let tampered = op
            .execute(
                DataPayload::text("tampered message"),
                serde_json::json!({
                    "action": "verify",
                    "public_key_hex": pk_hex,
                    "signature_hex": sig_hex
                }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(tampered["valid"], false);
    }

    #[tokio::test]
    async fn test_pqc_slh_dsa_and_falcon_honest_unsupported() {
        let ctx = ExecutionContext::new("t_pqc_slh");
        let slh = PqcOp {
            algorithm: "sphincs_plus".into(),
        };
        let res = slh
            .execute(
                DataPayload::text("slh test"),
                serde_json::json!({ "action": "roundtrip" }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(res["valid"], true);

        let falcon = PqcOp {
            algorithm: "falcon".into(),
        };
        assert_eq!(
            falcon.manifest().status,
            omni_core::FeatureStatus::Unsupported
        );
        assert!(falcon
            .execute(DataPayload::text("msg"), serde_json::json!({}), &ctx)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_all_hashes_and_xof_bounds() {
        let ctx = ExecutionContext::new("t_all_hashes");
        let input = DataPayload::text("abc");
        let algs = [
            ("md5", 32usize),
            ("sha1", 40),
            ("ripemd160", 40),
            ("sha224", 56),
            ("sha256", 64),
            ("sha384", 96),
            ("sha512", 128),
            ("sha512_224", 56),
            ("sha512_256", 64),
            ("sha3_224", 56),
            ("sha3_256", 64),
            ("sha3_384", 96),
            ("sha3_512", 128),
            ("shake128", 64),
            ("shake256", 128),
            ("blake2s", 64),
            ("blake2b", 128),
            ("blake3", 64),
            ("xxhash32", 8),
            ("xxhash64", 16),
            ("murmur3", 8),
        ];
        for (alg, expected_hex_len) in algs {
            let op = GenericHashOp {
                algorithm: alg.into(),
            };
            let out = op
                .execute(input.clone(), serde_json::json!({}), &ctx)
                .await
                .unwrap();
            assert_eq!(out.as_str().unwrap().len(), expected_hex_len, "alg={alg}");
        }
        // SHAKE OOM bounds guard
        let shake = GenericHashOp {
            algorithm: "shake256".into(),
        };
        assert!(shake
            .execute(input.clone(), serde_json::json!({ "length": 0 }), &ctx)
            .await
            .is_err());
        assert!(shake
            .execute(input, serde_json::json!({ "length": 99_999_999u64 }), &ctx)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_all_checksums_including_fletcher32_regression() {
        let ctx = ExecutionContext::new("t_all_chk");
        let algs = [
            ("crc8", 2usize),
            ("crc16", 4),
            ("crc32", 8),
            ("crc32_castagnoli", 8),
            ("crc64", 16),
            ("adler32", 8),
            ("fletcher16", 4),
            ("fletcher32", 8),
        ];
        for sample in [
            "",
            "a",
            "ab",
            "123456789",
            "The quick brown fox jumps over the lazy dog",
        ] {
            for (alg, hex_len) in algs {
                let op = ChecksumOp {
                    algorithm: alg.into(),
                };
                let out = op
                    .execute(DataPayload::text(sample), serde_json::json!({}), &ctx)
                    .await
                    .unwrap();
                assert_eq!(
                    out.as_str().unwrap().len(),
                    hex_len,
                    "alg={alg} sample={sample}"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_classical_ciphers_enigma_reciprocity_and_affine_negative() {
        let ctx = ExecutionContext::new("t_classical");

        // ROT5 / ROT18 / ROT47 involutions
        for (v, sample) in [
            ("5", "0123456789"),
            ("18", "Hello 12345"),
            ("47", "Omni!@#2026"),
        ] {
            let op = RotOp { variant: v.into() };
            let enc = op
                .execute(DataPayload::text(sample), serde_json::json!({}), &ctx)
                .await
                .unwrap();
            let dec = op.execute(enc, serde_json::json!({}), &ctx).await.unwrap();
            assert_eq!(dec.as_str().unwrap(), sample, "ROT{v} must be self-inverse");
        }

        // Affine with negative a and b
        let affine = AffineOp;
        let enc = affine
            .execute(
                DataPayload::text("AttackAtDawn"),
                serde_json::json!({ "a": -5, "b": -3 }),
                &ctx,
            )
            .await
            .unwrap();
        let dec = affine
            .execute(
                enc,
                serde_json::json!({ "a": -5, "b": -3, "decode": true }),
                &ctx,
            )
            .await
            .unwrap();
        assert_eq!(dec.as_str().unwrap(), "AttackAtDawn");
        assert!(affine
            .execute(
                DataPayload::text("hi"),
                serde_json::json!({ "a": 13 }),
                &ctx
            )
            .await
            .is_err());

        // Vigenere roundtrip
        let vig = VigenereOp;
        let enc_v = vig
            .execute(
                DataPayload::text("Hello World!"),
                serde_json::json!({ "key": "OMNI" }),
                &ctx,
            )
            .await
            .unwrap();
        let dec_v = vig
            .execute(
                enc_v,
                serde_json::json!({ "key": "OMNI", "decode": true }),
                &ctx,
            )
            .await
            .unwrap();
        assert_eq!(dec_v.as_str().unwrap(), "Hello World!");

        // Morse roundtrip
        let morse = MorseOp;
        let enc_m = morse
            .execute(DataPayload::text("SOS 2026"), serde_json::json!({}), &ctx)
            .await
            .unwrap();
        let dec_m = morse
            .execute(enc_m, serde_json::json!({ "decode": true }), &ctx)
            .await
            .unwrap();
        assert_eq!(dec_m.as_str().unwrap(), "SOS 2026");

        // Enigma MUST be strictly reciprocal (encrypting ciphertext with same positions recovers plaintext)
        let enigma = EnigmaOp;
        let cfg = serde_json::json!({ "pos1": 3, "pos2": 14, "pos3": 21 });
        let msg = "HELLOWORLDENIGMATESTMESSAGEWITHMANYCHARACTERSTOSTEPALLROTORS";
        let ct = enigma
            .execute(DataPayload::text(msg), cfg.clone(), &ctx)
            .await
            .unwrap();
        assert_ne!(ct.as_str().unwrap(), msg);
        // No character ever encrypts to itself in Enigma!
        for (a, b) in msg.chars().zip(ct.as_str().unwrap().chars()) {
            assert_ne!(a, b, "Enigma letter must never map to itself");
        }
        let pt = enigma.execute(ct, cfg, &ctx).await.unwrap();
        assert_eq!(pt.as_str().unwrap(), msg);
    }

    #[tokio::test]
    async fn test_symmetric_all_ciphers_and_short_iv_guard() {
        let ctx = ExecutionContext::new("t_sym_all");
        for cipher in ["aes-256-gcm", "aes-128-gcm", "chacha20poly1305", "rc4"] {
            let op = SymmetricOp {
                cipher: cipher.into(),
            };
            let ct = op
                .execute(
                    DataPayload::text("secret data"),
                    serde_json::json!({}),
                    &ctx,
                )
                .await
                .unwrap();
            let pt = op
                .execute(ct, serde_json::json!({ "decode": true }), &ctx)
                .await
                .unwrap();
            assert_eq!(pt.into_text().unwrap(), "secret data", "cipher={cipher}");
        }
        // Short IV must return Validation error, NEVER panic in Nonce::from_slice
        for cipher in ["aes-256-gcm", "aes-128-gcm", "chacha20poly1305"] {
            let op = SymmetricOp {
                cipher: cipher.into(),
            };
            let res = op
                .execute(
                    DataPayload::text("hello"),
                    serde_json::json!({ "iv": "010203" }),
                    &ctx,
                )
                .await;
            assert!(res.is_err(), "short IV must be rejected for {cipher}");
        }
    }

    #[tokio::test]
    async fn test_asymmetric_rsa_ed25519_and_kdfs() {
        let ctx = ExecutionContext::new("t_asym_kdf");

        // Ed25519 keygen + sign + verify + tamper
        let ed = Ed25519Op;
        let kp = ed
            .execute(
                DataPayload::text(""),
                serde_json::json!({ "action": "keygen" }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        let sig = ed
            .execute(
                DataPayload::text("hello"),
                serde_json::json!({ "action": "sign", "secret_key_hex": kp["secret_key_hex"] }),
                &ctx,
            )
            .await
            .unwrap()
            .into_text()
            .unwrap();
        let ok = ed.execute(DataPayload::text("hello"), serde_json::json!({ "action": "verify", "public_key_hex": kp["public_key_hex"], "signature_hex": sig }), &ctx).await.unwrap().into_json().unwrap();
        assert_eq!(ok["valid"], true);
        let bad = ed.execute(DataPayload::text("tampered"), serde_json::json!({ "action": "verify", "public_key_hex": kp["public_key_hex"], "signature_hex": sig }), &ctx).await.unwrap().into_json().unwrap();
        assert_eq!(bad["valid"], false);

        // RSA 1024-bit roundtrip + invalid bit guard
        let rsa = RsaOp;
        assert!(rsa
            .execute(
                DataPayload::text(""),
                serde_json::json!({ "action": "keygen", "bits": 64 }),
                &ctx
            )
            .await
            .is_err());
        let rkp = rsa
            .execute(
                DataPayload::text(""),
                serde_json::json!({ "action": "keygen", "bits": 1024 }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        let ct = rsa
            .execute(
                DataPayload::text("rsa payload"),
                serde_json::json!({ "action": "encrypt", "public_key_pem": rkp["public_key_pem"] }),
                &ctx,
            )
            .await
            .unwrap();
        let pt = rsa.execute(ct, serde_json::json!({ "action": "decrypt", "private_key_pem": rkp["private_key_pem"] }), &ctx).await.unwrap();
        assert_eq!(pt.into_text().unwrap(), "rsa payload");

        // KDFs + bounds validation
        for (alg, cfg) in [
            ("argon2id", serde_json::json!({})),
            ("argon2i", serde_json::json!({})),
            ("argon2d", serde_json::json!({})),
            ("bcrypt", serde_json::json!({ "cost": 4 })),
            ("scrypt", serde_json::json!({})),
            ("pbkdf2", serde_json::json!({ "rounds": 1000 })),
            ("hkdf", serde_json::json!({ "info": "test" })),
        ] {
            let op = KdfOp {
                algorithm: alg.into(),
            };
            let out = op
                .execute(DataPayload::text("password123"), cfg, &ctx)
                .await
                .unwrap();
            assert!(!out.as_str().unwrap().is_empty(), "kdf={alg}");
        }
        assert!(KdfOp {
            algorithm: "bcrypt".into()
        }
        .execute(
            DataPayload::text("p"),
            serde_json::json!({ "cost": 31 }),
            &ctx
        )
        .await
        .is_err());
        assert!(KdfOp {
            algorithm: "pbkdf2".into()
        }
        .execute(
            DataPayload::text("p"),
            serde_json::json!({ "rounds": 0 }),
            &ctx
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn test_jwt_alg_enforcement_and_auth_signatures_and_lsb_bounds() {
        let ctx = ExecutionContext::new("t_jwt_sig");
        use base64::prelude::*;
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        // Construct valid HS256 JWT
        let h = BASE64_URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let p = BASE64_URL_SAFE_NO_PAD.encode(r#"{"sub":"alice"}"#);
        let mut mac = Hmac::<Sha256>::new_from_slice(b"mysecret").unwrap();
        mac.update(format!("{h}.{p}").as_bytes());
        let s = BASE64_URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        let jwt = format!("{h}.{p}.{s}");

        let jwt_op = JwtDebuggerOp;
        let ok = jwt_op
            .execute(
                DataPayload::text(&jwt),
                serde_json::json!({ "secret": "mysecret" }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(ok["verified"], true);

        // alg: none MUST NEVER verify
        let h_none = BASE64_URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
        let mut mac2 = Hmac::<Sha256>::new_from_slice(b"mysecret").unwrap();
        mac2.update(format!("{h_none}.{p}").as_bytes());
        let s2 = BASE64_URL_SAFE_NO_PAD.encode(mac2.finalize().into_bytes());
        let none_jwt = format!("{h_none}.{p}.{s2}");
        let res_none = jwt_op
            .execute(
                DataPayload::text(&none_jwt),
                serde_json::json!({ "secret": "mysecret" }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(res_none["verified"], false);

        // 4-part malformed JWT rejected
        assert!(jwt_op
            .execute(DataPayload::text("a.b.c.d"), serde_json::json!({}), &ctx)
            .await
            .is_err());

        // Signatures: PKCE + AWS SigV4 + OAuth 1.0a
        let sig_op = SignaturesOp;
        let pkce = sig_op
            .execute(
                DataPayload::text(""),
                serde_json::json!({ "type": "pkce" }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(pkce["code_challenge_method"], "S256");
        let sigv4 = sig_op
            .execute(
                DataPayload::text(""),
                serde_json::json!({ "type": "aws_sigv4" }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(sigv4["signature"].as_str().unwrap().len(), 64);
        let oauth = sig_op.execute(DataPayload::text(""), serde_json::json!({ "type": "oauth1a", "consumer_secret": "cs", "token_secret": "ts", "base_string": "GET&http%3A%2F%2Fexample.com&" }), &ctx).await.unwrap().into_json().unwrap();
        assert!(!oauth["signature"].as_str().unwrap().is_empty());

        // LSB stego OOB regression: 40-byte carrier claiming len=5 bytes (5*8=40, but 32 bits already used by header -> needs 72!)
        let mut crafted = vec![0u8; 40];
        // Embed big-endian u32 = 5 in LSBs of bytes 0..32 (binary ...101 at bits 29, 30, 31)
        crafted[29] = 1;
        crafted[31] = 1;
        let lsb = LsbSteganographyOp;
        assert!(lsb
            .execute(
                DataPayload::bytes(crafted),
                serde_json::json!({ "action": "extract" }),
                &ctx
            )
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_enigma_historical_vector_and_double_stepping_and_pki_rejection() {
        let ctx = ExecutionContext::new("t_enigma_hist");

        // Famous historical Enigma I test vector: Rotors I-II-III, Reflector B, positions AAA (0,0,0)
        // Encrypting "AAAAA" produces "BDZGO"
        let enigma = EnigmaOp;
        let out = enigma
            .execute(
                DataPayload::text("AAAAA"),
                serde_json::json!({ "pos1": 0, "pos2": 0, "pos3": 0 }),
                &ctx,
            )
            .await
            .unwrap();
        assert_eq!(out.as_str().unwrap(), "BDZGO");

        // Double-stepping notch crossing (pos2=4 'E', pos3=21 'V') must remain strictly reciprocal
        // and never encrypt any letter to itself
        let msg = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG";
        let cfg = serde_json::json!({ "pos1": 0, "pos2": 3, "pos3": 20 });
        let ct = enigma
            .execute(DataPayload::text(msg), cfg.clone(), &ctx)
            .await
            .unwrap();
        let ct_str = ct.as_str().unwrap().to_string();
        for (a, b) in msg.chars().zip(ct_str.chars()) {
            assert_ne!(a, b, "Enigma must never map a letter to itself");
        }
        let pt = enigma
            .execute(DataPayload::text(&ct_str), cfg, &ctx)
            .await
            .unwrap();
        assert_eq!(pt.as_str().unwrap(), msg);

        // X509InspectOp rejects invalid PEM/DER gracefully
        assert!(X509InspectOp
            .execute(
                DataPayload::text(
                    "  -----BEGIN CERTIFICATE-----\nINVALID\n-----END CERTIFICATE-----"
                ),
                serde_json::json!({}),
                &ctx,
            )
            .await
            .is_err());
        assert!(X509InspectOp
            .execute(
                DataPayload::bytes(vec![0x30, 0x00]),
                serde_json::json!({}),
                &ctx,
            )
            .await
            .is_err());
    }
}
