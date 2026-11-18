pub mod internals;
pub mod ocr;
pub mod ops;
pub mod scrubber;

pub use internals::PdfInternalsOp;
pub use ocr::PdfOcrLayoutOp;
pub use ops::PdfMultiToolOp;
pub use scrubber::PdfScrubberOp;

use omni_core::OmniResult;
use omni_registry::OperationRegistry;
use std::sync::Arc;

pub fn register_pdf(registry: &mut OperationRegistry) -> OmniResult<()> {
    registry.register(Arc::new(PdfMultiToolOp))?;
    registry.register(Arc::new(PdfInternalsOp))?;
    registry.register(Arc::new(PdfScrubberOp))?;
    registry.register(Arc::new(PdfOcrLayoutOp))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lopdf::{dictionary, Document, Object, Stream};
    use omni_core::{DataPayload, ExecutionContext, Operation};

    fn create_test_pdf() -> Vec<u8> {
        let mut doc = Document::with_version("1.5");
        let pages_id = doc.new_object_id();
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font",
            "Subtype" => "Type1",
            "BaseFont" => "Helvetica",
        });
        let resources_id = doc.add_object(dictionary! {
            "Font" => dictionary! {
                "F1" => font_id,
            },
        });
        let content = doc.add_object(Stream::new(
            dictionary! {},
            b"BT /F1 12 Tf 72 712 Td (Hello OMNI PDF) Tj ET".to_vec(),
        ));
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "Contents" => content,
        });
        let pages = dictionary! {
            "Type" => "Pages",
            "Kids" => vec![page_id.into()],
            "Count" => 1,
            "Resources" => resources_id,
            "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        };
        doc.objects.insert(pages_id, Object::Dictionary(pages));
        let catalog_id = doc.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
        });
        doc.trailer.set("Root", catalog_id);
        doc.trailer.set(
            "Info",
            dictionary! {
                "Author" => "Test Author",
                "Producer" => "OMNI Builder",
            },
        );

        let mut buf = Vec::new();
        doc.save_to(&mut buf).unwrap();
        buf
    }

    #[tokio::test]
    async fn test_pdf_multitool_info_and_rotate() {
        let pdf_bytes = create_test_pdf();
        let op = PdfMultiToolOp;
        let ctx = ExecutionContext::new("t_pdf");

        let res = op
            .execute(
                DataPayload::bytes(pdf_bytes.clone()),
                serde_json::json!({ "action": "info" }),
                &ctx,
            )
            .await
            .unwrap();

        let json = res.into_json().unwrap();
        assert_eq!(json["page_count"], 1);

        // Test rotation
        let res_rot = op
            .execute(
                DataPayload::bytes(pdf_bytes),
                serde_json::json!({ "action": "rotate", "degrees": 180 }),
                &ctx,
            )
            .await
            .unwrap();
        assert!(!res_rot.into_bytes().is_empty());
    }

    #[tokio::test]
    async fn test_pdf_scrubber() {
        let pdf_bytes = create_test_pdf();
        let op = PdfScrubberOp;
        let ctx = ExecutionContext::new("t_scrub");

        let res = op
            .execute(DataPayload::bytes(pdf_bytes), serde_json::json!({}), &ctx)
            .await
            .unwrap();

        let scrubbed_bytes = res.into_bytes();
        let scrubbed_doc = Document::load_mem(&scrubbed_bytes).unwrap();
        assert!(scrubbed_doc.trailer.get(b"Info").is_err());
    }

    #[tokio::test]
    async fn test_pdf_internals() {
        let pdf_bytes = create_test_pdf();
        let op = PdfInternalsOp;
        let ctx = ExecutionContext::new("t_internals");

        let res = op
            .execute(
                DataPayload::bytes(pdf_bytes),
                serde_json::json!({ "action": "inspect" }),
                &ctx,
            )
            .await
            .unwrap();

        let json = res.into_json().unwrap();
        assert_eq!(json["pages"], 1);
        assert!(json["total_objects"].as_u64().unwrap() > 0);
    }

    #[tokio::test]
    async fn test_pdf_rotation_validation_indirect_info_scrub_and_malformed_inputs() {
        let ctx = ExecutionContext::new("t_pdf_edge");

        // 1. Non-multiple-of-90 rotation MUST be rejected per ISO 32000-1
        let pdf = create_test_pdf();
        assert!(PdfMultiToolOp
            .execute(
                DataPayload::bytes(pdf.clone()),
                serde_json::json!({ "action": "rotate", "degrees": 45 }),
                &ctx,
            )
            .await
            .is_err());

        // Negative -90 normalizes cleanly to 270
        let rot270 = PdfMultiToolOp
            .execute(
                DataPayload::bytes(pdf),
                serde_json::json!({ "action": "rotate", "degrees": -90 }),
                &ctx,
            )
            .await
            .unwrap()
            .into_bytes();
        let rot_doc = Document::load_mem(&rot270).unwrap();
        let page_id = *rot_doc.get_pages().values().next().unwrap();
        assert_eq!(
            rot_doc
                .get_object(page_id)
                .unwrap()
                .as_dict()
                .unwrap()
                .get(b"Rotate")
                .unwrap()
                .as_i64()
                .unwrap(),
            270
        );

        // 2. Indirect /Info object with custom key MUST be completely deleted from doc.objects
        let mut doc = Document::with_version("1.5");
        let pages_id = doc.new_object_id();
        let page_id = doc.add_object(dictionary! { "Type" => "Page", "Parent" => pages_id });
        doc.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![page_id.into()],
                "Count" => 1,
            }),
        );
        let catalog_id = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        let info_id = doc.add_object(dictionary! {
            "Author" => "Secret Agent",
            "CustomInternalSecret" => "TOP_SECRET_MARKER_XYZ",
        });
        doc.trailer.set("Root", catalog_id);
        doc.trailer.set("Info", info_id);
        let mut raw_pdf = Vec::new();
        doc.save_to(&mut raw_pdf).unwrap();

        let scrubbed = PdfScrubberOp
            .execute(DataPayload::bytes(raw_pdf), serde_json::json!({}), &ctx)
            .await
            .unwrap()
            .into_bytes();
        let scrubbed_str = String::from_utf8_lossy(&scrubbed);
        assert!(
            !scrubbed_str.contains("TOP_SECRET_MARKER_XYZ"),
            "indirect /Info object leaked after scrub"
        );

        // 3. Corrupted PDF bytes must fail cleanly across all PDF ops
        let garbage = b"%PDF-1.5\ncorrupt garbage bytes".to_vec();
        assert!(PdfInternalsOp
            .execute(
                DataPayload::bytes(garbage.clone()),
                serde_json::json!({}),
                &ctx
            )
            .await
            .is_err());
        assert!(PdfMultiToolOp
            .execute(
                DataPayload::bytes(garbage.clone()),
                serde_json::json!({}),
                &ctx
            )
            .await
            .is_err());
        assert!(PdfScrubberOp
            .execute(DataPayload::bytes(garbage), serde_json::json!({}), &ctx)
            .await
            .is_err());
    }
}
