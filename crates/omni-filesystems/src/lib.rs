pub mod archive;
pub mod fs_forensics;
pub mod serialization;
pub mod sql_engine;

pub use archive::ArchiveToolkitOp;
pub use fs_forensics::FilesystemForensicsOp;
pub use serialization::BinaryFormatsOp;
pub use sql_engine::EmbeddedSqlOp;

use omni_core::OmniResult;
use omni_registry::OperationRegistry;
use std::sync::Arc;

pub fn register_filesystems(registry: &mut OperationRegistry) -> OmniResult<()> {
    registry.register(Arc::new(EmbeddedSqlOp))?;
    registry.register(Arc::new(BinaryFormatsOp))?;
    registry.register(Arc::new(ArchiveToolkitOp))?;
    registry.register(Arc::new(FilesystemForensicsOp))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use omni_core::{DataPayload, ExecutionContext, Operation};

    #[tokio::test]
    async fn test_embedded_sql_analytics() {
        let op = EmbeddedSqlOp;
        let ctx = ExecutionContext::new("t_sql");

        let csv_data = "name,role,salary\nAlice,Engineer,120000\nBob,Designer,95000\nCharlie,Engineer,130000";
        let res = op
            .execute(
                DataPayload::text(csv_data),
                serde_json::json!({
                    "query": "SELECT role, COUNT(*) as count, AVG(CAST(salary as INTEGER)) as avg_salary FROM data GROUP BY role ORDER BY avg_salary DESC"
                }),
                &ctx,
            )
            .await
            .unwrap();

        let json = res.into_json().unwrap();
        assert_eq!(json["row_count"], 2);
        let first_row = &json["rows"][0];
        assert_eq!(first_row["role"], "Engineer");
        assert_eq!(first_row["count"], 2);
        assert_eq!(first_row["avg_salary"], 125000.0);
    }

    #[tokio::test]
    async fn test_protobuf_wire_decoding() {
        let op = BinaryFormatsOp;
        let ctx = ExecutionContext::new("t_pb");

        // Protobuf message: field 1 (varint 150), field 2 (string "testing")
        // Field 1: (1 << 3) | 0 = 0x08, value 150 = 0x96, 0x01
        // Field 2: (2 << 3) | 2 = 0x12, len 7 = 0x07, "testing"
        let mut pb_bytes = vec![0x08, 0x96, 0x01, 0x12, 0x07];
        pb_bytes.extend_from_slice(b"testing");

        let res = op
            .execute(DataPayload::bytes(pb_bytes), serde_json::json!({ "format": "protobuf" }), &ctx)
            .await
            .unwrap();

        let json = res.into_json().unwrap();
        assert_eq!(json["fields_count"], 2);
        assert_eq!(json["fields"][0]["field_number"], 1);
        assert_eq!(json["fields"][0]["value"], 150);
        assert_eq!(json["fields"][1]["field_number"], 2);
        assert_eq!(json["fields"][1]["value"]["string"], "testing");
    }

    #[tokio::test]
    async fn test_mbr_partition_parsing() {
        let op = FilesystemForensicsOp;
        let ctx = ExecutionContext::new("t_mbr");

        let mut mbr = vec![0u8; 512];
        mbr[510] = 0x55;
        mbr[511] = 0xAA;

        // Partition 1 at offset 446
        let p1 = &mut mbr[446..462];
        p1[0] = 0x80; // bootable
        p1[4] = 0x07; // NTFS
        p1[8..12].copy_from_slice(&2048u32.to_le_bytes()); // start LBA
        p1[12..16].copy_from_slice(&2097152u32.to_le_bytes()); // 1GB in sectors

        let res = op
            .execute(DataPayload::bytes(mbr), serde_json::json!({}), &ctx)
            .await
            .unwrap();

        let json = res.into_json().unwrap();
        assert_eq!(json["active_partitions_count"], 1);
        let part = &json["partitions"][0];
        assert_eq!(part["bootable"], true);
        assert_eq!(part["type_name"], "NTFS / exFAT");
        assert_eq!(part["size_mb"], 1024);
    }
}
