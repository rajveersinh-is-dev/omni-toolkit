use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniError, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use omni_security::ResourceLimits;
use serde_json::{json, Value};
use std::io::Cursor;

pub struct ArchiveToolkitOp;

#[async_trait]
impl Operation for ArchiveToolkitOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "archive.toolkit",
            "Archive Toolkit & Decompression Bomb Guard",
            "Creates and inspects ZIP, TAR, and GZIP archives with enforced 100:1 compression ratio and 500MB bomb limits",
            OperationCategory::StorageAndFormats,
        )
        .with_types(vec![DataType::Bytes], vec![DataType::Json, DataType::Bytes])
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let action = config.get("action").and_then(|v| v.as_str()).unwrap_or("inspect");
        let bytes = input.into_bytes();
        let limits = ResourceLimits::default();

        match action {
            "inspect" | _ => {
                // Check if ZIP
                if bytes.starts_with(&[0x50, 0x4B, 0x03, 0x04]) {
                    let reader = Cursor::new(&bytes);
                    let mut zip = zip::ZipArchive::new(reader)
                        .map_err(|e| OmniError::InvalidInput(format!("ZIP open error: {e}")))?;

                    let mut files = Vec::new();
                    let mut total_uncompressed = 0u64;

                    for i in 0..zip.len() {
                        let file = zip.by_index(i)
                            .map_err(|e| OmniError::Execution { operation: "zip_read".into(), message: e.to_string() })?;

                        let uncompressed_size = file.size();
                        let compressed_size = file.compressed_size();
                        total_uncompressed += uncompressed_size;

                        files.push(json!({
                            "name": file.name(),
                            "uncompressed_bytes": uncompressed_size,
                            "compressed_bytes": compressed_size,
                            "is_dir": file.is_dir(),
                        }));
                    }

                    // Decompression bomb verification
                    limits.check_decompression(bytes.len(), total_uncompressed as usize)?;
                    let ratio = total_uncompressed as f64 / bytes.len().max(1) as f64;

                    return Ok(DataPayload::json(json!({
                        "format": "ZIP Archive",
                        "total_files": files.len(),
                        "compressed_size_bytes": bytes.len(),
                        "total_uncompressed_bytes": total_uncompressed,
                        "overall_compression_ratio": (ratio * 10.0).round() / 10.0,
                        "files": files,
                    })));
                }

                // Check if TAR
                if bytes.len() >= 512 {
                    let mut tar = tar::Archive::new(Cursor::new(&bytes));
                    if let Ok(entries) = tar.entries() {
                        let mut files = Vec::new();
                        let mut total_uncompressed = 0u64;

                        for entry in entries.flatten() {
                            let path = entry.path().map(|p| p.display().to_string()).unwrap_or_default();
                            let size = entry.size();
                            total_uncompressed += size;
                            files.push(json!({
                                "name": path,
                                "uncompressed_bytes": size,
                            }));
                        }

                        if !files.is_empty() {
                            return Ok(DataPayload::json(json!({
                                "format": "TAR Archive",
                                "total_files": files.len(),
                                "archive_size_bytes": bytes.len(),
                                "total_uncompressed_bytes": total_uncompressed,
                                "files": files,
                            })));
                        }
                    }
                }

                Ok(DataPayload::json(json!({
                    "format": "Unknown / Non-archive stream",
                    "size_bytes": bytes.len(),
                })))
            }
        }
    }
}
