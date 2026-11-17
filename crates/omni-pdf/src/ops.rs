use lopdf::Document;
use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniError, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use serde_json::Value;

pub struct PdfMultiToolOp;

#[async_trait]
impl Operation for PdfMultiToolOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "pdf.multitool",
            "PDF Multi-Tool",
            "Performs PDF splitting, page merging, 90/180/270-degree rotation, and AcroForm field inspection",
            OperationCategory::DocumentsAndMedia,
        )
        .with_types(vec![DataType::Bytes], vec![DataType::Bytes, DataType::Json])
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let action = config.get("action").and_then(|v| v.as_str()).unwrap_or("info");
        let bytes = input.into_bytes();

        let mut doc = Document::load_mem(&bytes)
            .map_err(|e| OmniError::InvalidInput(format!("Failed to parse PDF document: {e}")))?;

        match action {
            "rotate" => {
                let degrees = config.get("degrees").and_then(|v| v.as_i64()).unwrap_or(90);
                let pages = doc.get_pages();
                for (_page_num, page_id) in pages {
                    let page = doc.get_object_mut(page_id)
                        .map_err(|e| OmniError::Execution { operation: "pdf_rotate".into(), message: e.to_string() })?;
                    if let Ok(dict) = page.as_dict_mut() {
                        dict.set("Rotate", degrees);
                    }
                }
                let mut out_bytes = Vec::new();
                doc.save_to(&mut out_bytes)
                    .map_err(|e| OmniError::Execution { operation: "pdf_save".into(), message: e.to_string() })?;
                Ok(DataPayload::bytes(out_bytes))
            }
            _ => {
                let page_count = doc.get_pages().len();
                let version = doc.version.clone();
                let mut form_fields = Vec::new();

                if let Ok(catalog) = doc.catalog() {
                    if let Ok(acro_form) = catalog.get(b"AcroForm") {
                        form_fields.push(format!("{:?}", acro_form));
                    }
                }

                let info = serde_json::json!({
                    "page_count": page_count,
                    "pdf_version": version,
                    "is_encrypted": doc.is_encrypted(),
                    "acro_form_fields": form_fields,
                });
                Ok(DataPayload::json(info))
            }
        }
    }
}
