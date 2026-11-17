//! Example: Hashing and encoding large binary buffers using OMNI operations.

use omni_core::{DataPayload, ExecutionContext};
use omni_crypto::register_crypto;
use omni_registry::OperationRegistry;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== OMNI Example: Binary Buffer Hashing ===\n");

    let mut registry = OperationRegistry::new();
    register_crypto(&mut registry)?;

    let sha256_op = registry.get("crypto.hash.sha256").unwrap();
    let blake3_op = registry.get("crypto.hash.blake3").unwrap();
    let ctx = ExecutionContext::new("hash_job");

    let buffer = vec![0xAB; 64 * 1024]; // 64 KB binary pattern
    let payload = DataPayload::bytes(buffer);

    let sha256_res = sha256_op.execute(payload.clone(), serde_json::json!({}), &ctx).await?;
    let blake3_res = blake3_op.execute(payload, serde_json::json!({}), &ctx).await?;

    println!("Dataset Size : 64 KB (repeating 0xAB)");
    println!("SHA-256 Digest: {}", sha256_res.as_str()?);
    println!("BLAKE3  Digest: {}", blake3_res.as_str()?);

    Ok(())
}
