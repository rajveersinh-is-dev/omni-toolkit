pub mod extractor;

pub use extractor::FirmwareExtractorOp;

use omni_core::OmniResult;
use omni_registry::OperationRegistry;
use std::sync::Arc;

pub fn register_firmware(registry: &mut OperationRegistry) -> OmniResult<()> {
    registry.register(Arc::new(FirmwareExtractorOp))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use omni_core::{DataPayload, ExecutionContext, Operation};

    #[tokio::test]
    async fn test_firmware_signatures_and_entropy() {
        let mut firmware_image = vec![0x00u8; 512]; // padding / bootloader area
        // Embed a fake SquashFS signature
        firmware_image.extend_from_slice(b"hsqs\x00\x01\x02\x03");
        // Embed some pseudo-random high entropy bytes
        for i in 0..512 {
            firmware_image.push(((i * 73 + 19) % 256) as u8);
        }

        let op = FirmwareExtractorOp;
        let ctx = ExecutionContext::new("t_firmware");

        let res = op
            .execute(
                DataPayload::bytes(firmware_image),
                serde_json::json!({ "entropy_chunk_size": 256 }),
                &ctx,
            )
            .await
            .unwrap();

        let json = res.into_json().unwrap();
        assert!(json["total_signatures_found"].as_u64().unwrap() >= 1);
        let sig = &json["signatures"][0];
        assert!(sig["description"].as_str().unwrap().contains("Squashfs"));
    }
}
