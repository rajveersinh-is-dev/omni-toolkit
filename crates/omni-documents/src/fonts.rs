use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
};
use serde_json::Value;

pub struct FontToolkitOp;

fn select_font_name(face: &ttf_parser::Face<'_>, target_id: u16) -> Option<String> {
    let mut best: Option<(u8, String)> = None;
    for name in face.names() {
        if name.name_id != target_id {
            continue;
        }
        let Some(s) = name.to_string() else {
            continue;
        };
        if s.is_empty() {
            continue;
        }
        let priority = if name.is_unicode() && name.language_id == 0x0409 {
            3
        } else if name.is_unicode() {
            2
        } else {
            1
        };
        if best.as_ref().is_none_or(|(p, _)| priority > *p) {
            best = Some((priority, s));
        }
    }
    best.map(|(_, s)| s)
}

#[async_trait]
impl Operation for FontToolkitOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "doc.font_toolkit",
            "Font Toolkit & Inspector",
            "Inspects TrueType (TTF) and OpenType (OTF) font metadata, glyph counts, units per em, and table directories",
            OperationCategory::DocumentsAndMedia,
        )
        .with_types(vec![DataType::Bytes], vec![DataType::Json])
        .with_status(FeatureStatus::Verified)
    }

    async fn execute(
        &self,
        input: DataPayload,
        config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let face_index = match config.get("face_index") {
            None => 0u32,
            Some(v) => {
                let raw = v.as_u64().ok_or_else(|| {
                    OmniError::Validation("Font 'face_index' must be a non-negative integer".into())
                })?;
                u32::try_from(raw).map_err(|_| {
                    OmniError::Validation("Font 'face_index' exceeds u32 range".into())
                })?
            }
        };

        let bytes = input.into_bytes();
        let faces_in_collection = ttf_parser::fonts_in_collection(&bytes).unwrap_or(1);
        let face = ttf_parser::Face::parse(&bytes, face_index)
            .map_err(|e| OmniError::InvalidInput(format!("Failed to parse font file: {e:?}")))?;

        let family_name = select_font_name(&face, ttf_parser::name_id::FAMILY);
        let postscript_name = select_font_name(&face, ttf_parser::name_id::POST_SCRIPT_NAME);

        let mut tables: Vec<String> = face
            .raw_face()
            .table_records
            .into_iter()
            .map(|rec| rec.tag.to_string())
            .collect();
        tables.sort();

        let res = serde_json::json!({
            "family_name": family_name.unwrap_or_else(|| "Unknown".to_string()),
            "postscript_name": postscript_name.unwrap_or_else(|| "Unknown".to_string()),
            "units_per_em": face.units_per_em(),
            "number_of_glyphs": face.number_of_glyphs(),
            "is_monospaced": face.is_monospaced(),
            "ascender": face.ascender(),
            "descender": face.descender(),
            "line_gap": face.line_gap(),
            "is_variable": face.is_variable(),
            "faces_in_collection": faces_in_collection,
            "tables": tables,
        });

        Ok(DataPayload::json(res))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sfnt_table_checksum(data: &[u8]) -> u32 {
        let mut sum = 0u32;
        let (chunks, rem) = data.as_chunks::<4>();
        for &chunk in chunks {
            sum = sum.wrapping_add(u32::from_be_bytes(chunk));
        }
        if !rem.is_empty() {
            let mut tail = [0u8; 4];
            tail[..rem.len()].copy_from_slice(rem);
            sum = sum.wrapping_add(u32::from_be_bytes(tail));
        }
        sum
    }

    fn build_minimal_ttf_font() -> Vec<u8> {
        // 1. head table (54 bytes)
        let mut head = Vec::with_capacity(54);
        head.extend_from_slice(&1u16.to_be_bytes()); // majorVersion
        head.extend_from_slice(&0u16.to_be_bytes()); // minorVersion
        head.extend_from_slice(&0x0001_0000u32.to_be_bytes()); // fontRevision 1.0
        head.extend_from_slice(&0u32.to_be_bytes()); // checkSumAdjustment (filled below)
        head.extend_from_slice(&0x5F0F_3CF5u32.to_be_bytes()); // magicNumber
        head.extend_from_slice(&0u16.to_be_bytes()); // flags
        head.extend_from_slice(&1000u16.to_be_bytes()); // unitsPerEm
        head.extend_from_slice(&0i64.to_be_bytes()); // created
        head.extend_from_slice(&0i64.to_be_bytes()); // modified
        head.extend_from_slice(&0i16.to_be_bytes()); // xMin
        head.extend_from_slice(&(-200i16).to_be_bytes()); // yMin
        head.extend_from_slice(&800i16.to_be_bytes()); // xMax
        head.extend_from_slice(&800i16.to_be_bytes()); // yMax
        head.extend_from_slice(&0u16.to_be_bytes()); // macStyle
        head.extend_from_slice(&8u16.to_be_bytes()); // lowestRecPPEM
        head.extend_from_slice(&2i16.to_be_bytes()); // fontDirectionHint
        head.extend_from_slice(&0i16.to_be_bytes()); // indexToLocFormat (short)
        head.extend_from_slice(&0i16.to_be_bytes()); // glyphDataFormat
        assert_eq!(head.len(), 54);

        // 2. hhea table (36 bytes)
        let mut hhea = Vec::with_capacity(36);
        hhea.extend_from_slice(&1u16.to_be_bytes()); // majorVersion
        hhea.extend_from_slice(&0u16.to_be_bytes()); // minorVersion
        hhea.extend_from_slice(&820i16.to_be_bytes()); // ascender
        hhea.extend_from_slice(&(-180i16).to_be_bytes()); // descender
        hhea.extend_from_slice(&90i16.to_be_bytes()); // lineGap
        hhea.extend_from_slice(&600u16.to_be_bytes()); // advanceWidthMax
        hhea.extend_from_slice(&0i16.to_be_bytes()); // minLeftSideBearing
        hhea.extend_from_slice(&0i16.to_be_bytes()); // minRightSideBearing
        hhea.extend_from_slice(&600i16.to_be_bytes()); // xMaxExtent
        hhea.extend_from_slice(&1i16.to_be_bytes()); // caretSlopeRise
        hhea.extend_from_slice(&0i16.to_be_bytes()); // caretSlopeRun
        hhea.extend_from_slice(&0i16.to_be_bytes()); // caretOffset
        hhea.extend_from_slice(&[0u8; 8]); // 4 reserved i16s
        hhea.extend_from_slice(&0i16.to_be_bytes()); // metricDataFormat
        hhea.extend_from_slice(&1u16.to_be_bytes()); // numberOfHMetrics
        assert_eq!(hhea.len(), 36);

        // 3. maxp table (version 1.0, 32 bytes)
        let mut maxp = Vec::with_capacity(32);
        maxp.extend_from_slice(&0x0001_0000u32.to_be_bytes()); // version 1.0
        maxp.extend_from_slice(&42u16.to_be_bytes()); // numGlyphs
        maxp.extend_from_slice(&[0u8; 26]); // remaining TrueType maxp v1.0 fields
        assert_eq!(maxp.len(), 32);

        // 4. name table (format 0, Platform 3 Windows / Encoding 1 Unicode BMP / Language 0x0409)
        let encode_utf16be = |s: &str| -> Vec<u8> {
            let mut out = Vec::new();
            for unit in s.encode_utf16() {
                out.extend_from_slice(&unit.to_be_bytes());
            }
            out
        };
        let family_bytes = encode_utf16be("Omni Mono");
        let ps_bytes = encode_utf16be("OmniMono-Regular");
        let fr_family_bytes = encode_utf16be("Omni Mono FR");
        let cn_ps_bytes = encode_utf16be("宋体");
        let mut name = Vec::new();
        name.extend_from_slice(&0u16.to_be_bytes()); // format = 0
        name.extend_from_slice(&4u16.to_be_bytes()); // count = 4
        name.extend_from_slice(&(6u16 + 4 * 12).to_be_bytes()); // stringOffset = 54
        let mut str_offset = 0u16;
        let records = [
            (0x0409u16, ttf_parser::name_id::FAMILY, &family_bytes),
            (0x0409u16, ttf_parser::name_id::POST_SCRIPT_NAME, &ps_bytes),
            // Higher language IDs appear later in sorted name tables and must not clobber en-US
            (0x040Cu16, ttf_parser::name_id::FAMILY, &fr_family_bytes),
            (
                0x0804u16,
                ttf_parser::name_id::POST_SCRIPT_NAME,
                &cn_ps_bytes,
            ),
        ];
        for (lang_id, name_id, bytes) in records {
            name.extend_from_slice(&3u16.to_be_bytes()); // platformID = Windows
            name.extend_from_slice(&1u16.to_be_bytes()); // encodingID = Unicode BMP
            name.extend_from_slice(&lang_id.to_be_bytes());
            name.extend_from_slice(&name_id.to_be_bytes());
            name.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            name.extend_from_slice(&str_offset.to_be_bytes());
            str_offset += bytes.len() as u16;
        }
        for (_, _, bytes) in records {
            name.extend_from_slice(bytes);
        }

        // 5. post table (version 3.0, 32 bytes, isFixedPitch = 1)
        let mut post = Vec::with_capacity(32);
        post.extend_from_slice(&0x0003_0000u32.to_be_bytes()); // version 3.0
        post.extend_from_slice(&0u32.to_be_bytes()); // italicAngle
        post.extend_from_slice(&(-100i16).to_be_bytes()); // underlinePosition
        post.extend_from_slice(&50i16.to_be_bytes()); // underlineThickness
        post.extend_from_slice(&1u32.to_be_bytes()); // isFixedPitch = true
        post.extend_from_slice(&[0u8; 16]); // min/max mem fields
        assert_eq!(post.len(), 32);

        // Assemble sfnt offset table + sorted table directory + 4-byte aligned table payloads
        let tables: [([u8; 4], Vec<u8>); 5] = [
            (*b"head", head),
            (*b"hhea", hhea),
            (*b"maxp", maxp),
            (*b"name", name),
            (*b"post", post),
        ];

        let num_tables = tables.len() as u16;
        let max_pow2 = 1u16 << (15 - num_tables.leading_zeros());
        let search_range = max_pow2 * 16;
        let entry_selector = max_pow2.trailing_zeros() as u16;
        let range_shift = num_tables * 16 - search_range;

        let mut font = Vec::new();
        font.extend_from_slice(&0x0001_0000u32.to_be_bytes()); // sfntVersion (TrueType)
        font.extend_from_slice(&num_tables.to_be_bytes());
        font.extend_from_slice(&search_range.to_be_bytes());
        font.extend_from_slice(&entry_selector.to_be_bytes());
        font.extend_from_slice(&range_shift.to_be_bytes());

        let mut next_offset = 12usize + tables.len() * 16;
        let mut head_offset = 0usize;
        for (tag, data) in &tables {
            if tag == b"head" {
                head_offset = next_offset;
            }
            let checksum = sfnt_table_checksum(data);
            font.extend_from_slice(tag);
            font.extend_from_slice(&checksum.to_be_bytes());
            font.extend_from_slice(&(next_offset as u32).to_be_bytes());
            font.extend_from_slice(&(data.len() as u32).to_be_bytes());
            let padded_len = (data.len() + 3) & !3;
            next_offset += padded_len;
        }

        for (_, data) in &tables {
            font.extend_from_slice(data);
            let pad = (4 - (data.len() % 4)) % 4;
            font.resize(font.len() + pad, 0);
        }

        // Write valid head.checkSumAdjustment = 0xB1B0AFBA - whole_font_checksum
        let whole_checksum = sfnt_table_checksum(&font);
        let adjustment = 0xB1B0_AFBAu32.wrapping_sub(whole_checksum);
        font[head_offset + 8..head_offset + 12].copy_from_slice(&adjustment.to_be_bytes());

        font
    }

    #[tokio::test]
    async fn test_font_toolkit_valid_minimal_ttf() {
        let ctx = ExecutionContext::new("t_font_pos");
        let font_bytes = build_minimal_ttf_font();

        let json = FontToolkitOp
            .execute(DataPayload::bytes(font_bytes), serde_json::json!({}), &ctx)
            .await
            .unwrap()
            .into_json()
            .unwrap();

        assert_eq!(json["family_name"], "Omni Mono");
        assert_eq!(json["postscript_name"], "OmniMono-Regular");
        assert_eq!(json["units_per_em"], 1000);
        assert_eq!(json["number_of_glyphs"], 42);
        assert_eq!(json["is_monospaced"], true);
        assert_eq!(json["ascender"], 820);
        assert_eq!(json["descender"], -180);
        assert_eq!(json["line_gap"], 90);
        assert_eq!(json["is_variable"], false);
        assert_eq!(json["faces_in_collection"], 1);
        assert_eq!(
            json["tables"],
            serde_json::json!(["head", "hhea", "maxp", "name", "post"])
        );
    }

    #[tokio::test]
    async fn test_font_toolkit_rejects_empty_and_truncated_fonts() {
        let ctx = ExecutionContext::new("t_font_neg");
        assert!(FontToolkitOp
            .execute(DataPayload::bytes(Vec::new()), serde_json::json!({}), &ctx)
            .await
            .is_err());
        assert!(FontToolkitOp
            .execute(
                DataPayload::bytes(vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x05]),
                serde_json::json!({}),
                &ctx,
            )
            .await
            .is_err());
        assert!(FontToolkitOp
            .execute(
                DataPayload::bytes(build_minimal_ttf_font()),
                serde_json::json!({ "face_index": -1 }),
                &ctx,
            )
            .await
            .is_err());
        assert!(FontToolkitOp
            .execute(
                DataPayload::bytes(build_minimal_ttf_font()),
                serde_json::json!({ "face_index": 5 }),
                &ctx,
            )
            .await
            .is_err());
    }
}
