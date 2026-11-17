use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniError, OmniResult, Operation,
    OperationCategory, OperationManifest,
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
    }

    async fn execute(&self, input: DataPayload, _config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let bytes = input.into_bytes();

        // Check if PEM or raw DER
        let der = if bytes.starts_with(b"-----BEGIN") {
            let pem_str = std::str::from_utf8(&bytes)
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
            "subject_alternative_names": sans,
            "version": cert.version().0,
            "signature_algorithm": cert.signature_algorithm.algorithm.to_string(),
        });

        Ok(DataPayload::json(info))
    }
}
