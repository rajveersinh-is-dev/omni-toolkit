use lopdf::{Document, Object};
use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
};
use serde_json::Value;

pub struct PdfScrubberOp;

#[async_trait]
impl Operation for PdfScrubberOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "pdf.scrubber",
            "PDF Metadata Sanitizer & Scrubber",
            "Permanently and irreversibly removes PDF /Info dictionaries, Author, Creator, Producer, Dates, and XML /Metadata streams",
            OperationCategory::DocumentsAndMedia,
        )
        .with_types(vec![DataType::Bytes], vec![DataType::Bytes])
        .with_status(FeatureStatus::Verified)
    }

    async fn execute(
        &self,
        input: DataPayload,
        _config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let bytes = input.into_bytes();
        let mut doc = Document::load_mem(&bytes)
            .map_err(|e| OmniError::InvalidInput(format!("Failed to parse PDF: {e}")))?;

        // 1. Capture and remove trailer /Info reference or dict (and its indirect object)
        let mut to_remove = Vec::new();
        if let Ok(Object::Reference(info_id)) = doc.trailer.get(b"Info") {
            to_remove.push(*info_id);
        }
        doc.trailer.remove(b"Info");

        // 2. Scan and sanitize all objects that are /Info or /Metadata
        for ((id, gen), obj) in &mut doc.objects {
            if let Object::Dictionary(dict) = obj {
                if let Ok(Object::Reference(meta_id)) = dict.get(b"Metadata") {
                    to_remove.push(*meta_id);
                }
                dict.remove(b"Author");
                dict.remove(b"Creator");
                dict.remove(b"Producer");
                dict.remove(b"CreationDate");
                dict.remove(b"ModDate");
                dict.remove(b"Title");
                dict.remove(b"Subject");
                dict.remove(b"Keywords");
                dict.remove(b"Metadata");

                if let Ok(t) = dict.get(b"Type") {
                    if t == &Object::Name(b"Metadata".to_vec()) {
                        to_remove.push((*id, *gen));
                    }
                }
            } else if let Object::Stream(stream) = obj {
                if let Ok(Object::Reference(meta_id)) = stream.dict.get(b"Metadata") {
                    to_remove.push(*meta_id);
                }
                stream.dict.remove(b"Metadata");
                if let Ok(t) = stream.dict.get(b"Type") {
                    if t == &Object::Name(b"Metadata".to_vec()) {
                        to_remove.push((*id, *gen));
                    }
                }
            }
        }

        for (id, gen) in to_remove {
            doc.objects.remove(&(id, gen));
        }

        let mut out = Vec::new();
        doc.save_to(&mut out).map_err(|e| OmniError::Execution {
            operation: "pdf_scrub".into(),
            message: e.to_string(),
        })?;

        Ok(DataPayload::bytes(out))
    }
}
