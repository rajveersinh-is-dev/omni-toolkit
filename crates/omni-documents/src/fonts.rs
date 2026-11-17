use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniError, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use serde_json::Value;

pub struct FontToolkitOp;

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
    }

    async fn execute(&self, input: DataPayload, _config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let bytes = input.into_bytes();
        let face = ttf_parser::Face::parse(&bytes, 0)
            .map_err(|e| OmniError::InvalidInput(format!("Failed to parse font file: {e:?}")))?;

        let mut family_name = None;
        let mut postscript_name = None;

        for name in face.names() {
            if name.name_id == ttf_parser::name_id::FAMILY {
                if let Some(s) = name.to_string() {
                    family_name = Some(s);
                }
            } else if name.name_id == ttf_parser::name_id::POST_SCRIPT_NAME {
                if let Some(s) = name.to_string() {
                    postscript_name = Some(s);
                }
            }
        }

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
        });

        Ok(DataPayload::json(res))
    }
}
