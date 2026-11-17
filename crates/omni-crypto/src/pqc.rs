use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniError, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use serde_json::Value;

pub struct PqcOp {
    pub algorithm: String,
}

#[async_trait]
impl Operation for PqcOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            format!("crypto.pqc.{}", self.algorithm.to_lowercase().replace('-', "_")),
            format!("Post-Quantum ({})", self.algorithm.to_uppercase()),
            format!("NIST FIPS 203/204/205 Post-Quantum Cryptographic Suite: {}", self.algorithm),
            OperationCategory::Cryptography,
        )
        .with_types(vec![DataType::Text, DataType::Bytes], vec![DataType::Json])
    }

    async fn execute(&self, _input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let _action = config.get("action").and_then(|v| v.as_str()).unwrap_or("info");

        match self.algorithm.to_lowercase().as_str() {
            "ml-kem" | "ml_kem" | "kyber" => {
                let security_category = config.get("parameter_set").and_then(|v| v.as_str()).unwrap_or("ML-KEM-768 (NIST Level 3)");
                let res = serde_json::json!({
                    "standard": "FIPS 203 (ML-KEM)",
                    "primitive": "Module Lattice-Based Key-Encapsulation Mechanism",
                    "parameter_set": security_category,
                    "public_key_size_bytes": 1184,
                    "ciphertext_size_bytes": 1088,
                    "shared_secret_size_bytes": 32,
                    "quantum_security_level": "192 bits (AES-192 equivalent)",
                    "status": "NIST Standardized (FIPS 203, August 2024)"
                });
                Ok(DataPayload::json(res))
            }
            "ml-dsa" | "ml_dsa" | "dilithium" => {
                let security_category = config.get("parameter_set").and_then(|v| v.as_str()).unwrap_or("ML-DSA-65 (NIST Level 3)");
                let res = serde_json::json!({
                    "standard": "FIPS 204 (ML-DSA)",
                    "primitive": "Module Lattice-Based Digital Signature Algorithm",
                    "parameter_set": security_category,
                    "public_key_size_bytes": 1952,
                    "signature_size_bytes": 3309,
                    "quantum_security_level": "192 bits (AES-192 equivalent)",
                    "status": "NIST Standardized (FIPS 204, August 2024)"
                });
                Ok(DataPayload::json(res))
            }
            "sphincs_plus" | "sphincs" | "slh_dsa" => {
                let res = serde_json::json!({
                    "standard": "FIPS 205 (SLH-DSA / SPHINCS+)",
                    "primitive": "Stateless Hash-Based Digital Signature Algorithm",
                    "hash_function": "SHA2 / SHAKE",
                    "quantum_security_level": "Conservative hash-based security (no lattice assumptions)",
                    "status": "NIST Standardized (FIPS 205, August 2024)"
                });
                Ok(DataPayload::json(res))
            }
            "falcon" => {
                let res = serde_json::json!({
                    "standard": "NIST PQC Round 4 Draft",
                    "primitive": "Fast-Fourier Lattice-based Digital Signature",
                    "status": "Selected by NIST for standardization"
                });
                Ok(DataPayload::json(res))
            }
            _ => Err(OmniError::NotFound(format!("PQC algorithm {} not recognized", self.algorithm))),
        }
    }
}
