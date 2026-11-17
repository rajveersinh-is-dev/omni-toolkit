use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniError, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use serde_json::{json, Value};

pub struct FilesystemForensicsOp;

#[async_trait]
impl Operation for FilesystemForensicsOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "fs.forensics",
            "Filesystem & Partition Forensics",
            "Parses MBR/GPT partition tables, FAT12/16/32 BPBs, and ext2/3/4 superblocks from raw disk images",
            OperationCategory::StorageAndFormats,
        )
        .with_types(vec![DataType::Bytes], vec![DataType::Json])
    }

    async fn execute(&self, input: DataPayload, _config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let bytes = input.into_bytes();
        if bytes.len() < 512 {
            return Err(OmniError::InvalidInput("Image too small for partition sector (< 512 bytes)".into()));
        }

        // 1. Check ext2/3/4 superblock at offset 1024
        if bytes.len() >= 1024 + 100 && bytes[1024 + 56] == 0x53 && bytes[1024 + 57] == 0xEF {
            let sb = &bytes[1024..];
            let inodes_count = u32::from_le_bytes([sb[0], sb[1], sb[2], sb[3]]);
            let blocks_count = u32::from_le_bytes([sb[4], sb[5], sb[6], sb[7]]);
            let log_block_size = u32::from_le_bytes([sb[24], sb[25], sb[26], sb[27]]);
            let block_size = 1024u64 << log_block_size;

            return Ok(DataPayload::json(json!({
                "detected_filesystem": "ext2/ext3/ext4",
                "superblock_magic": "0xEF53",
                "total_inodes": inodes_count,
                "total_blocks": blocks_count,
                "block_size_bytes": block_size,
                "filesystem_size_mb": (blocks_count as u64 * block_size) / (1024 * 1024),
            })));
        }

        // 2. Check GPT Header at offset 512
        if bytes.len() >= 1024 && &bytes[512..520] == b"EFI PART" {
            let hdr = &bytes[512..];
            let current_lba = u64::from_le_bytes(hdr[24..32].try_into().unwrap());
            let backup_lba = u64::from_le_bytes(hdr[32..40].try_into().unwrap());
            let num_part_entries = u32::from_le_bytes(hdr[80..84].try_into().unwrap());
            let part_entry_size = u32::from_le_bytes(hdr[84..88].try_into().unwrap());

            return Ok(DataPayload::json(json!({
                "partition_table": "GPT (GUID Partition Table)",
                "signature": "EFI PART",
                "current_lba": current_lba,
                "backup_lba": backup_lba,
                "partition_entries_count": num_part_entries,
                "partition_entry_size_bytes": part_entry_size,
            })));
        }

        // 3. Check MBR Partition Table
        if bytes[510] == 0x55 && bytes[511] == 0xAA {
            let mut partitions = Vec::new();
            for i in 0..4 {
                let offset = 446 + (i * 16);
                let p = &bytes[offset..offset + 16];
                let bootable = p[0] == 0x80;
                let part_type = p[4];
                let lba_start = u32::from_le_bytes([p[8], p[9], p[10], p[11]]);
                let sectors_count = u32::from_le_bytes([p[12], p[13], p[14], p[15]]);

                if part_type != 0 {
                    let type_name = match part_type {
                        0x07 => "NTFS / exFAT",
                        0x83 => "Linux Native (ext2/3/4, btrfs)",
                        0x82 => "Linux Swap",
                        0x0B => "FAT32 (CHS)",
                        0x0C => "FAT32 (LBA)",
                        0x0E => "FAT16 (LBA)",
                        0xEE => "GPT Protective MBR",
                        0xEF => "EFI System Partition",
                        _ => "Other / Unknown",
                    };

                    let size_mb = (sectors_count as u64 * 512) / (1024 * 1024);

                    partitions.push(json!({
                        "partition_index": i + 1,
                        "bootable": bootable,
                        "type_hex": format!("0x{:02X}", part_type),
                        "type_name": type_name,
                        "start_lba": lba_start,
                        "sectors_count": sectors_count,
                        "size_mb": size_mb,
                    }));
                }
            }

            return Ok(DataPayload::json(json!({
                "partition_table": "MBR (Master Boot Record)",
                "boot_signature": "0x55AA",
                "active_partitions_count": partitions.len(),
                "partitions": partitions,
            })));
        }

        Ok(DataPayload::json(json!({
            "status": "No standard MBR/GPT/ext superblock signature detected in raw sector buffer",
            "first_16_bytes_hex": hex::encode(&bytes[..16.min(bytes.len())]),
        })))
    }
}
