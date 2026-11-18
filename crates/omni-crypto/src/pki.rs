use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
};
use serde_json::Value;
use x509_parser::prelude::*;

pub struct X509InspectOp;

#[async_trait]
impl Operation for X509InspectOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "crypto.pki.x509_inspect",
            "X.509 Certificate Inspector",
            "Parses X.509 certificates (PEM or DER), extracting SANs, issuer, validity, and public key metadata",
            OperationCategory::Cryptography,
        )
        .with_types(vec![DataType::Text, DataType::Bytes], vec![DataType::Json])
        .with_status(FeatureStatus::Verified)
    }

    async fn execute(
        &self,
        input: DataPayload,
        _config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let bytes = input.into_bytes();

        // Check if PEM (ignoring UTF-8 BOM, leading whitespace, or OpenSSL text preamble) or raw DER
        let stripped = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(&bytes);
        let trimmed_start = stripped
            .iter()
            .position(|b| !b.is_ascii_whitespace())
            .unwrap_or(stripped.len());
        let is_pem = stripped[trimmed_start..].starts_with(b"-----BEGIN")
            || std::str::from_utf8(stripped).is_ok_and(|s| s.contains("-----BEGIN "));
        let der = if is_pem {
            let pem_str = std::str::from_utf8(&stripped[trimmed_start..])
                .map_err(|e| OmniError::InvalidInput(format!("Invalid PEM string: {e}")))?;
            let (_, pem) = parse_x509_pem(pem_str.as_bytes())
                .map_err(|e| OmniError::InvalidInput(format!("X509 PEM parse error: {e}")))?;
            pem.contents
        } else {
            bytes
        };

        let (_, cert) = parse_x509_certificate(&der)
            .map_err(|e| OmniError::InvalidInput(format!("X509 DER parse error: {e}")))?;

        let subject = cert.subject().to_string();
        let issuer = cert.issuer().to_string();
        let serial = cert.raw_serial_as_string();
        let not_before = cert.validity().not_before.to_string();
        let not_after = cert.validity().not_after.to_string();
        let spki = cert.public_key();
        let public_key_algorithm = spki.algorithm.algorithm.to_string();
        let public_key_bits = spki
            .subject_public_key
            .data
            .len()
            .saturating_mul(8)
            .saturating_sub(usize::from(spki.subject_public_key.unused_bits));

        let mut sans = Vec::new();
        if let Ok(Some(ext)) = cert.subject_alternative_name() {
            for name in &ext.value.general_names {
                sans.push(format!("{:?}", name));
            }
        }

        let info = serde_json::json!({
            "subject": subject,
            "issuer": issuer,
            "serial_number": serial,
            "validity": {
                "not_before": not_before,
                "not_after": not_after,
            },
            "public_key": {
                "algorithm": public_key_algorithm,
                "bit_length": public_key_bits,
            },
            "subject_alternative_names": sans,
            "version": cert.version().0,
            "signature_algorithm": cert.signature_algorithm.algorithm.to_string(),
        });

        Ok(DataPayload::json(info))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    use ed25519_dalek::{Signer, SigningKey};

    fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = content.len();
        if len < 0x80 {
            out.push(len as u8);
        } else if len <= 0xFF {
            out.push(0x81);
            out.push(len as u8);
        } else {
            out.push(0x82);
            out.push((len >> 8) as u8);
            out.push((len & 0xFF) as u8);
        }
        out.extend_from_slice(content);
        out
    }

    fn der_seq(items: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        for item in items {
            body.extend_from_slice(item);
        }
        der_tlv(0x30, &body)
    }

    fn der_set(items: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        for item in items {
            body.extend_from_slice(item);
        }
        der_tlv(0x31, &body)
    }

    fn der_rdn(oid_bytes: &[u8], value: &str) -> Vec<u8> {
        let atv = der_seq(&[der_tlv(0x06, oid_bytes), der_tlv(0x0C, value.as_bytes())]);
        der_set(&[atv])
    }

    fn build_minimal_x509_v3_der() -> Vec<u8> {
        let signing_key = SigningKey::from_bytes(&[0x42u8; 32]);
        let verifying_key = signing_key.verifying_key();

        // OID 1.3.101.112 (id-Ed25519): 0x2B, 0x65, 0x70
        let ed25519_oid = [0x2Bu8, 0x65, 0x70];
        let sig_alg = der_seq(&[der_tlv(0x06, &ed25519_oid)]);

        // Version [0] EXPLICIT INTEGER 2 (X.509 v3)
        let version = der_tlv(0xA0, &der_tlv(0x02, &[0x02]));

        // Serial number: 0x01020304 -> "01:02:03:04"
        let serial = der_tlv(0x02, &[0x01, 0x02, 0x03, 0x04]);

        // OID 2.5.4.3 (CN): 0x55, 0x04, 0x03; OID 2.5.4.10 (O): 0x55, 0x04, 0x0A
        let oid_cn = [0x55u8, 0x04, 0x03];
        let oid_o = [0x55u8, 0x04, 0x0A];

        let issuer = der_seq(&[
            der_rdn(&oid_o, "OMNI Security"),
            der_rdn(&oid_cn, "OMNI Test CA"),
        ]);

        // Validity: UTCTime (tag 0x17)
        let validity = der_seq(&[
            der_tlv(0x17, b"250101000000Z"),
            der_tlv(0x17, b"350101000000Z"),
        ]);

        let subject = der_seq(&[
            der_rdn(&oid_o, "OMNI Security"),
            der_rdn(&oid_cn, "omni.example.test"),
        ]);

        // SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier(Ed25519), BIT STRING(0x00 || pubkey) }
        let mut pk_bits = vec![0x00];
        pk_bits.extend_from_slice(verifying_key.as_bytes());
        let spki = der_seq(&[sig_alg.clone(), der_tlv(0x03, &pk_bits)]);

        // SAN Extension: OID 2.5.29.17 (0x55, 0x1D, 0x11)
        // GeneralNames ::= SEQUENCE { dNSName [2] IA5String, dNSName [2] IA5String }
        let san_values = der_seq(&[
            der_tlv(0x82, b"omni.example.test"),
            der_tlv(0x82, b"api.omni.example.test"),
        ]);
        let san_ext = der_seq(&[
            der_tlv(0x06, &[0x55, 0x1D, 0x11]),
            der_tlv(0x04, &san_values),
        ]);
        let extensions = der_tlv(0xA3, &der_seq(&[san_ext]));

        // TBSCertificate
        let tbs = der_seq(&[
            version,
            serial,
            sig_alg.clone(),
            issuer,
            validity,
            subject,
            spki,
            extensions,
        ]);

        // Real Ed25519 signature over TBSCertificate DER bytes
        let signature = signing_key.sign(&tbs);
        let mut sig_bits = vec![0x00];
        sig_bits.extend_from_slice(&signature.to_bytes());

        // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
        der_seq(&[tbs, sig_alg, der_tlv(0x03, &sig_bits)])
    }

    #[tokio::test]
    async fn test_x509_inspect_valid_der_and_pem_with_leading_whitespace() {
        let ctx = ExecutionContext::new("t_x509_pos");
        let der = build_minimal_x509_v3_der();

        let der_json = X509InspectOp
            .execute(DataPayload::bytes(der.clone()), serde_json::json!({}), &ctx)
            .await
            .unwrap()
            .into_json()
            .unwrap();

        assert_eq!(der_json["subject"], "O=OMNI Security, CN=omni.example.test");
        assert_eq!(der_json["issuer"], "O=OMNI Security, CN=OMNI Test CA");
        assert_eq!(der_json["serial_number"], "01:02:03:04");
        assert_eq!(der_json["version"], 2);
        assert_eq!(der_json["signature_algorithm"], "1.3.101.112");
        assert_eq!(der_json["public_key"]["algorithm"], "1.3.101.112");
        assert_eq!(der_json["public_key"]["bit_length"], 256);
        assert_eq!(
            der_json["validity"]["not_before"],
            "Jan  1 00:00:00 2025 +00:00"
        );
        assert_eq!(
            der_json["validity"]["not_after"],
            "Jan  1 00:00:00 2035 +00:00"
        );
        assert_eq!(
            der_json["subject_alternative_names"],
            serde_json::json!([
                "DNSName(\"omni.example.test\")",
                "DNSName(\"api.omni.example.test\")"
            ])
        );

        // Wrap DER as PEM with leading whitespace and verify identical parsed output
        let b64 = BASE64.encode(&der);
        let wrapped: Vec<&str> = b64
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        let pem = format!(
            "  \n\t-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            wrapped.join("\n")
        );

        let pem_json = X509InspectOp
            .execute(DataPayload::text(pem.clone()), serde_json::json!({}), &ctx)
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(pem_json, der_json);

        // UTF-8 BOM + PEM and OpenSSL preamble + PEM must also parse identically
        let mut bom_pem = vec![0xEF, 0xBB, 0xBF];
        bom_pem.extend_from_slice(pem.trim_start().as_bytes());
        let bom_json = X509InspectOp
            .execute(DataPayload::bytes(bom_pem), serde_json::json!({}), &ctx)
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(bom_json, der_json);

        let preamble_pem = format!(
            "Bag Attributes\n    friendlyName: OMNI Test\n{}",
            pem.trim_start()
        );
        let preamble_json = X509InspectOp
            .execute(DataPayload::text(preamble_pem), serde_json::json!({}), &ctx)
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(preamble_json, der_json);
    }

    #[tokio::test]
    async fn test_x509_inspect_rejects_empty_and_corrupt_inputs() {
        let ctx = ExecutionContext::new("t_x509_neg");
        assert!(X509InspectOp
            .execute(DataPayload::bytes(Vec::new()), serde_json::json!({}), &ctx)
            .await
            .is_err());
        assert!(X509InspectOp
            .execute(
                DataPayload::text("   -----BEGIN CERTIFICATE-----\n@@@\n-----END CERTIFICATE-----"),
                serde_json::json!({}),
                &ctx,
            )
            .await
            .is_err());
    }
}
