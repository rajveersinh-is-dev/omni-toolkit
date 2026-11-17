pub mod diagrams;
pub mod fonts;
pub mod math;
pub mod transcode;

pub use diagrams::DiagramCompilerOp;
pub use fonts::FontToolkitOp;
pub use math::MathTypesetOp;
pub use transcode::DocumentTranscodeOp;

use omni_core::OmniResult;
use omni_registry::OperationRegistry;
use std::sync::Arc;

pub fn register_documents(registry: &mut OperationRegistry) -> OmniResult<()> {
    registry.register(Arc::new(DocumentTranscodeOp))?;
    registry.register(Arc::new(FontToolkitOp))?;
    registry.register(Arc::new(MathTypesetOp))?;
    registry.register(Arc::new(DiagramCompilerOp))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use omni_core::{DataPayload, ExecutionContext, Operation};

    #[tokio::test]
    async fn test_markdown_to_html() {
        let op = DocumentTranscodeOp;
        let ctx = ExecutionContext::new("t_doc");

        let md = "# Title\n\nThis is **bold** and *italic* text.";
        let res = op
            .execute(
                DataPayload::text(md),
                serde_json::json!({ "from": "markdown", "to": "html" }),
                &ctx,
            )
            .await
            .unwrap();

        let html = res.into_text().unwrap();
        assert!(html.contains("<h1>Title</h1>"));
        assert!(html.contains("<strong>bold</strong>"));
    }

    #[tokio::test]
    async fn test_math_typesetting_svg() {
        let op = MathTypesetOp;
        let ctx = ExecutionContext::new("t_math");

        let math = "E = mc^2";
        let res = op
            .execute(
                DataPayload::text(math),
                serde_json::json!({ "format": "svg" }),
                &ctx,
            )
            .await
            .unwrap();

        let svg = res.into_text().unwrap();
        assert!(svg.starts_with("<svg"));
        assert!(svg.contains("E = mc^2"));
    }

    #[tokio::test]
    async fn test_diagram_compiler_svg() {
        let op = DiagramCompilerOp;
        let ctx = ExecutionContext::new("t_diag");

        let diag = "graph TD\n  A[Input] --> B[Processing] --> C[Output]";
        let res = op
            .execute(
                DataPayload::text(diag),
                serde_json::json!({ "type": "mermaid" }),
                &ctx,
            )
            .await
            .unwrap();

        let svg = res.into_text().unwrap();
        assert!(svg.starts_with("<svg"));
        assert!(svg.contains("Diagram Render"));
    }
}
