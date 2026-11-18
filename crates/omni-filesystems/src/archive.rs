use flate2::read::GzDecoder;
use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
};
use omni_security::{safe_join_no_symlinks, ResourceLimits};
use serde_json::{json, Value};
use std::io::{Cursor, Read};
use std::path::Path;

pub struct ArchiveToolkitOp;

#[async_trait]
impl Operation for ArchiveToolkitOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "archive.toolkit",
            "Archive Toolkit & Decompression Bomb Guard",
            "Inspects and validates ZIP, TAR, and GZIP archives with enforced decompression bomb limits (100:1 ratio, 500MB cap) and path-traversal detection",
            OperationCategory::StorageAndFormats,
        )
        .with_types(vec![DataType::Bytes], vec![DataType::Json, DataType::Bytes])
        .with_status(FeatureStatus::Verified)
        .with_limitations(vec![
            "Supports ZIP, TAR, and GZIP inspection/decompression; BZIP2, XZ, Zstd, 7z, RAR, ISO 9660, VHD, and VMDK are not implemented".into(),
        ])
        .with_tags(vec!["archive".into(), "zip".into(), "tar".into(), "gzip".into()])
    }

    async fn execute(
        &self,
        input: DataPayload,
        config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let action = config
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("inspect");
        let bytes = input.into_bytes();
        let limits = ResourceLimits::default();

        // 1. Check GZIP (magic 0x1F 0x8B)
        if bytes.starts_with(&[0x1F, 0x8B]) {
            let mut decoder = GzDecoder::new(Cursor::new(&bytes));
            let mut decompressed = Vec::new();
            let mut buf = [0u8; 8192];
            let mut total = 0usize;

            loop {
                let n = decoder
                    .read(&mut buf)
                    .map_err(|e| OmniError::InvalidInput(format!("GZIP decode error: {e}")))?;
                if n == 0 {
                    break;
                }
                total = total.saturating_add(n);
                // Enforce bomb limits incrementally BEFORE unbounded allocation!
                limits.check_decompression(bytes.len(), total)?;
                if action == "decompress" {
                    decompressed.extend_from_slice(&buf[..n]);
                }
            }

            if action == "decompress" {
                return Ok(DataPayload::bytes(decompressed));
            }

            let ratio = total as f64 / bytes.len().max(1) as f64;
            return Ok(DataPayload::json(json!({
                "format": "GZIP Stream",
                "compressed_size_bytes": bytes.len(),
                "uncompressed_size_bytes": total,
                "compression_ratio": (ratio * 10.0).round() / 10.0,
                "bomb_check": "passed",
            })));
        }

        // 2. Check ZIP (magic PK\x03\x04)
        if bytes.starts_with(&[0x50, 0x4B, 0x03, 0x04]) {
            let reader = Cursor::new(&bytes);
            let mut zip = zip::ZipArchive::new(reader)
                .map_err(|e| OmniError::InvalidInput(format!("ZIP open error: {e}")))?;

            let mut files = Vec::new();
            let mut total_uncompressed: u64 = 0;
            let sandbox_virtual = Path::new("omni_virtual_sandbox");

            for i in 0..zip.len() {
                let file = zip.by_index(i).map_err(|e| OmniError::Execution {
                    operation: "zip_read".into(),
                    message: e.to_string(),
                })?;

                let entry_name = file.name().to_string();
                let path_safe = safe_join_no_symlinks(sandbox_virtual, Path::new(&entry_name)).is_ok();
                let uncompressed_size = file.size();
                let compressed_size = file.compressed_size();
                total_uncompressed = total_uncompressed.saturating_add(uncompressed_size);

                // Check bomb limit per-entry using usize::try_from to prevent 32-bit overflow
                let total_usize = usize::try_from(total_uncompressed).unwrap_or(usize::MAX);
                limits.check_decompression(bytes.len(), total_usize)?;

                files.push(json!({
                    "name": entry_name,
                    "uncompressed_bytes": uncompressed_size,
                    "compressed_bytes": compressed_size,
                    "is_dir": file.is_dir(),
                    "path_safe": path_safe,
                }));
            }

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

        // 3. Check TAR
        if bytes.len() >= 512 {
            let mut tar = tar::Archive::new(Cursor::new(&bytes));
            if let Ok(entries) = tar.entries() {
                let mut files = Vec::new();
                let mut total_uncompressed = 0u64;
                let sandbox_virtual = Path::new("omni_virtual_sandbox");

                for entry in entries.flatten() {
                    let path = entry
                        .path()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default();
                    let path_safe = safe_join_no_symlinks(sandbox_virtual, Path::new(&path)).is_ok();
                    let size = entry.size();
                    total_uncompressed = total_uncompressed.saturating_add(size);

                    let total_usize = usize::try_from(total_uncompressed).unwrap_or(usize::MAX);
                    limits.check_size(total_usize)?;

                    files.push(json!({
                        "name": path,
                        "uncompressed_bytes": size,
                        "path_safe": path_safe,
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
