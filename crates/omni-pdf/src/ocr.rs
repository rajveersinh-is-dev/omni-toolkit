use lopdf::Document;
use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniError, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use serde_json::{json, Value};

pub struct PdfOcrLayoutOp;

#[async_trait]
impl Operation for PdfOcrLayoutOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "pdf.ocr",
            "PDF Text & Layout Analyzer",
            "Extracts raw textual content, paragraph blocks, and layout bounding box approximations from PDF pages",
            OperationCategory::DocumentsAndMedia,
        )
        .with_types(vec![DataType::Bytes], vec![DataType::Json, DataType::Text])
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let output_format = config.get("format").and_then(|v| v.as_str()).unwrap_or("json");
        let bytes = input.into_bytes();

        let doc = Document::load_mem(&bytes)
            .map_err(|e| OmniError::InvalidInput(format!("Failed to parse PDF document: {e}")))?;

        let pages = doc.get_pages();
        let mut page_results = Vec::new();
        let mut full_text = String::new();

        for (page_num, _page_id) in pages {
            let extracted = doc.extract_text(&[page_num]).unwrap_or_default();
            let lines: Vec<&str> = extracted.lines().filter(|l| !l.trim().is_empty()).collect();
            
            let mut blocks = Vec::new();
            for (idx, line) in lines.iter().enumerate() {
                blocks.push(json!({
                    "line_index": idx,
                    "text": line,
                    "estimated_bbox": {
                        "x": 54.0,
                        "y": 72.0 + (idx as f64 * 14.0),
                        "width": (line.len() as f64 * 7.2).min(500.0),
                        "height": 12.0
                    }
                }));
            }

            page_results.push(json!({
                "page_number": page_num,
                "line_count": lines.len(),
                "blocks": blocks,
            }));

            full_text.push_str(&format!("--- Page {} ---\n", page_num));
            full_text.push_str(&extracted);
            full_text.push('\n');
        }

        if output_format == "text" {
            Ok(DataPayload::text(full_text))
        } else {
            Ok(DataPayload::json(json!({
                "total_pages": page_results.len(),
                "pages": page_results,
            })))
        }
    }
}
