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

        let csv_data =
            "name,role,salary\nAlice,Engineer,120000\nBob,Designer,95000\nCharlie,Engineer,130000";
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
            .execute(
                DataPayload::bytes(pb_bytes),
                serde_json::json!({ "format": "protobuf" }),
                &ctx,
            )
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

    #[tokio::test]
    async fn test_fs_ext_shift_overflow_and_serialization_overflow_guards() {
        let ctx = ExecutionContext::new("t_fs_edge");

        // 1. Ext superblock with malicious log_block_size = 99 MUST NOT panic with shift overflow!
        let mut bad_ext = vec![0u8; 2048];
        bad_ext[1024 + 56] = 0x53;
        bad_ext[1024 + 57] = 0xEF;
        bad_ext[1024 + 24..1024 + 28].copy_from_slice(&99u32.to_le_bytes());
        assert!(FilesystemForensicsOp
            .execute(DataPayload::bytes(bad_ext), serde_json::json!({}), &ctx)
            .await
            .is_err());

        // 2. GPT header parsing without unwraps
        let mut gpt = vec![0u8; 1024];
        gpt[512..520].copy_from_slice(b"EFI PART");
        gpt[512 + 24..512 + 32].copy_from_slice(&1u64.to_le_bytes());
        gpt[512 + 80..512 + 84].copy_from_slice(&128u32.to_le_bytes());
        let gpt_res = FilesystemForensicsOp
            .execute(DataPayload::bytes(gpt), serde_json::json!({}), &ctx)
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(gpt_res["partition_entries_count"], 128);

        // 3. Adversarial Protobuf huge varint length (u64::MAX) MUST NOT overflow offset + len!
        let bad_pb = vec![
            0x12, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01,
        ];
        let pb_res = BinaryFormatsOp
            .execute(
                DataPayload::bytes(bad_pb),
                serde_json::json!({ "format": "protobuf" }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(pb_res["fields_count"], 0);

        // 4. Adversarial ASN.1 DER 16-byte length-of-length MUST NOT panic or overflow!
        let bad_der = vec![0x30, 0x90, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let der_res = BinaryFormatsOp
            .execute(
                DataPayload::bytes(bad_der),
                serde_json::json!({ "format": "asn1" }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(der_res["total_elements"], 0);
    }

    #[tokio::test]
    async fn test_sql_json_column_alignment_readonly_and_binary_formats() {
        let ctx = ExecutionContext::new("t_fs_deep");

        // 1. JSON keys where unsanitized sort order ("-z" < "a") differs from sanitized order ("a" < "z")
        // Previously scrambled column values!
        let rows = serde_json::json!([
            { "-z": "val_z", "a": "val_a" }
        ]);
        let sql_res = EmbeddedSqlOp
            .execute(
                DataPayload::json(rows),
                serde_json::json!({ "query": "SELECT a, z FROM data" }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(sql_res["rows"][0]["a"], "val_a");
        assert_eq!(sql_res["rows"][0]["z"], "val_z");

        // Duplicate sanitized column names ("a-b" and "ab") must deduplicate instead of failing CREATE TABLE
        let dup_rows = serde_json::json!([{ "a-b": "first", "ab": "second" }]);
        let dup_res = EmbeddedSqlOp
            .execute(
                DataPayload::json(dup_rows),
                serde_json::json!({ "query": "SELECT * FROM data" }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(dup_res["row_count"], 1);

        // CTE write bypass ("WITH x AS (...) DELETE FROM data") MUST be rejected by engine readonly check!
        assert!(EmbeddedSqlOp
            .execute(
                DataPayload::text("id\n1\n"),
                serde_json::json!({ "query": "WITH x AS (SELECT 1) DELETE FROM data" }),
                &ctx,
            )
            .await
            .is_err());

        // Empty delimiter must be rejected
        assert!(EmbeddedSqlOp
            .execute(
                DataPayload::text("a,b\n1,2\n"),
                serde_json::json!({ "delimiter": "" }),
                &ctx,
            )
            .await
            .is_err());

        // 2. Truncated Protobuf varint must NOT fabricate a 0 field
        let trunc_pb = vec![0x08, 0x80];
        let pb_res = BinaryFormatsOp
            .execute(
                DataPayload::bytes(trunc_pb),
                serde_json::json!({ "format": "protobuf" }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(pb_res["fields_count"], 0);

        // Valid MessagePack + ASN.1 DER
        let msgpack_bytes = rmp_serde::to_vec(&serde_json::json!({"ok": true, "n": 42})).unwrap();
        let mp_res = BinaryFormatsOp
            .execute(
                DataPayload::bytes(msgpack_bytes),
                serde_json::json!({ "format": "msgpack" }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(mp_res["data"]["n"], 42);

        // ASN.1 DER: UTF8String "Hi" (tag 0x0C, len 2, 0x48, 0x69)
        let der = vec![0x0C, 0x02, b'H', b'i'];
        let der_res = BinaryFormatsOp
            .execute(
                DataPayload::bytes(der),
                serde_json::json!({ "format": "der" }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(der_res["total_elements"], 1);
        assert_eq!(der_res["elements"][0]["tag_type"], "UTF8String");
        assert_eq!(der_res["elements"][0]["string_repr"], "Hi");
    }

    #[tokio::test]
    async fn test_sql_rfc4180_quoted_csv_tsv_and_custom_delimiters() {
        let ctx = ExecutionContext::new("t_sql_rfc4180");

        // 1. RFC 4180 CSV with embedded commas, escaped "" quotes, and embedded newlines
        let rfc_csv = concat!(
            "\"full_name\",\"title\",\"notes\",score\n",
            "\"Smith, Alice\",\"Principal \"\"Lead\"\" Engineer\",\"Line 1\nLine 2\",98\n",
            "\"Doe, Bob\",\"Designer, Senior\",\"Simple note\",85\n",
            "\"Lee, Carol\",\"QA \"\"Automation\"\"\",short\n",
        );

        let filtered = EmbeddedSqlOp
            .execute(
                DataPayload::text(rfc_csv),
                serde_json::json!({
                    "query": "SELECT full_name, title, notes, score FROM data WHERE full_name = 'Smith, Alice'"
                }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(filtered["row_count"], 1);
        assert_eq!(filtered["rows"][0]["full_name"], "Smith, Alice");
        assert_eq!(filtered["rows"][0]["title"], "Principal \"Lead\" Engineer");
        assert_eq!(filtered["rows"][0]["notes"], "Line 1\nLine 2");
        assert_eq!(filtered["rows"][0]["score"], "98");

        // Verify all 3 rows parsed intact and short row padded with empty string
        let all = EmbeddedSqlOp
            .execute(
                DataPayload::text(rfc_csv),
                serde_json::json!({
                    "query": "SELECT full_name, title, score FROM data ORDER BY full_name ASC"
                }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(all["row_count"], 3);
        assert_eq!(all["rows"][0]["full_name"], "Doe, Bob");
        assert_eq!(all["rows"][0]["title"], "Designer, Senior");
        assert_eq!(all["rows"][1]["full_name"], "Lee, Carol");
        assert_eq!(all["rows"][1]["title"], "QA \"Automation\"");
        assert_eq!(all["rows"][1]["score"], "");

        // 2. Custom single-byte delimiter (TSV with quoted tab and escaped quote)
        let tsv = "name\tdesc\n\"Alpha\tOne\"\t\"Quote \"\"OK\"\"\"\nBeta\tPlain\n";
        let tsv_res = EmbeddedSqlOp
            .execute(
                DataPayload::text(tsv),
                serde_json::json!({
                    "delimiter": "\t",
                    "query": "SELECT name, desc FROM data WHERE name = 'Alpha\tOne'"
                }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(tsv_res["row_count"], 1);
        assert_eq!(tsv_res["rows"][0]["name"], "Alpha\tOne");
        assert_eq!(tsv_res["rows"][0]["desc"], "Quote \"OK\"");

        // 3. Custom multi-character delimiter ("::") with RFC 4180 quoting, escaped "" and embedded newlines
        let multi = "\"k::id\"::\"v\"\"desc\"\n\"foo::1\"::\"line 1\nline 2\"\n\"baz\"::\"qux\"\n";
        let multi_res = EmbeddedSqlOp
            .execute(
                DataPayload::text(multi),
                serde_json::json!({
                    "delimiter": "::",
                    "query": "SELECT kid, vdesc FROM data ORDER BY kid ASC"
                }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(multi_res["row_count"], 2);
        assert_eq!(multi_res["rows"][0]["kid"], "baz");
        assert_eq!(multi_res["rows"][0]["vdesc"], "qux");
        assert_eq!(multi_res["rows"][1]["kid"], "foo::1");
        assert_eq!(multi_res["rows"][1]["vdesc"], "line 1\nline 2");

        // 4. Leading whitespace-only lines, UTF-8 BOM, middle blank lines, and multiline SELECT queries
        let padded_csv = "\u{feff}   \n\t\n\"a\",b\n1,2\n   \n3,4\n";
        let padded_res = EmbeddedSqlOp
            .execute(
                DataPayload::text(padded_csv),
                serde_json::json!({
                    "query": "SELECT\n  a, b\nFROM data\nWHERE a != 'ATTACH'"
                }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(padded_res["row_count"], 2);
        assert_eq!(padded_res["rows"][0]["a"], "1");
        assert_eq!(padded_res["rows"][1]["b"], "4");

        // 5. CR/LF delimiters, newline-separated ATTACH bypass, and empty/whitespace-only inputs rejected cleanly
        assert!(EmbeddedSqlOp
            .execute(
                DataPayload::text("a,b\n1,2\n"),
                serde_json::json!({ "delimiter": "\n" }),
                &ctx,
            )
            .await
            .is_err());
        assert!(EmbeddedSqlOp
            .execute(
                DataPayload::text("a,b\n1,2\n"),
                serde_json::json!({ "delimiter": "\r" }),
                &ctx,
            )
            .await
            .is_err());
        assert!(EmbeddedSqlOp
            .execute(
                DataPayload::text("a,b\n1,2\n"),
                serde_json::json!({ "query": "SELECT 1; ATTACH\nDATABASE ':memory:' AS aux" }),
                &ctx,
            )
            .await
            .is_err());
        assert!(EmbeddedSqlOp
            .execute(
                DataPayload::text("   \n\r\n  "),
                serde_json::json!({}),
                &ctx,
            )
            .await
            .is_err());
    }
}
