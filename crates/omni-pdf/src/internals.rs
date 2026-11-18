use lopdf::{Document, Object};
use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
};
use serde_json::{json, Value};

pub struct PdfInternalsOp;

#[async_trait]
impl Operation for PdfInternalsOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "pdf.internals",
            "PDF Structure & Stream Inspector",
            "Inspects PDF object hierarchy, decompresses FlateDecode/ASCIIHex streams, and analyzes revision history",
            OperationCategory::DocumentsAndMedia,
        )
        .with_types(vec![DataType::Bytes], vec![DataType::Json, DataType::Bytes])
        .with_status(FeatureStatus::Verified)
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

        let mut doc = Document::load_mem(&bytes)
            .map_err(|e| OmniError::InvalidInput(format!("Failed to parse PDF: {e}")))?;

        match action {
            "decompress_all" => {
                doc.decompress();
                let mut out = Vec::new();
                doc.save_to(&mut out).map_err(|e| OmniError::Execution {
                    operation: "pdf_decompress".into(),
                    message: e.to_string(),
                })?;
                Ok(DataPayload::bytes(out))
            }
            _ => {
                let mut objects_summary = Vec::new();
                for ((id, gen), obj) in &doc.objects {
                    let type_name = match obj {
                        Object::Array(_) => "Array",
                        Object::Boolean(_) => "Boolean",
                        Object::Dictionary(d) => {
                            if let Ok(Object::Name(_n)) = d.get(b"Type") {
                                "Dict:Name"
                            } else {
                                "Dictionary"
                            }
                        }
                        Object::Integer(_) => "Integer",
                        Object::Real(_) => "Real",
                        Object::Name(_) => "Name",
                        Object::String(_, _) => "String",
                        Object::Stream(_) => "Stream",
                        Object::Null => "Null",
                        Object::Reference(_) => "Reference",
                    };
                    objects_summary.push(json!({
                        "id": id,
                        "generation": gen,
                        "type": type_name,
                        "is_stream": matches!(obj, Object::Stream(_)),
                    }));
                }

                let pages_count = doc.get_pages().len();
                let is_encrypted = doc.is_encrypted();
                let version = doc.version.clone();

                let res = json!({
                    "version": version,
                    "pages": pages_count,
                    "is_encrypted": is_encrypted,
                    "total_objects": doc.objects.len(),
                    "objects": objects_summary.into_iter().take(100).collect::<Vec<_>>(),
                });

                Ok(DataPayload::json(res))
            }
        }
    }
}
