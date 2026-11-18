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
    async fn test_math_typesetting_svg_and_mathml() {
        let op = MathTypesetOp;
        let ctx = ExecutionContext::new("t_math");

        let math = r"E = \frac{m c^2}{\sqrt{1 - \beta^2}}";
        let svg_res = op
            .execute(
                DataPayload::text(math),
                serde_json::json!({ "format": "svg" }),
                &ctx,
            )
            .await
            .unwrap();
        let svg = svg_res.into_text().unwrap();
        assert!(svg.starts_with("<svg"));
        assert!(svg.contains("<line")); // fraction bar rendered
        assert!(svg.contains("<polyline")); // square root radical rendered
        assert!(svg.contains("β")); // Greek symbol decoded

        let mathml_res = op
            .execute(
                DataPayload::text(math),
                serde_json::json!({ "format": "mathml" }),
                &ctx,
            )
            .await
            .unwrap();
        let mathml = mathml_res.into_text().unwrap();
        assert!(mathml.contains("<mfrac>"));
        assert!(mathml.contains("<msup>"));
        assert!(mathml.contains("<msqrt>"));
    }

    #[tokio::test]
    async fn test_diagram_compiler_svg() {
        let op = DiagramCompilerOp;
        let ctx = ExecutionContext::new("t_diag");

        let diag = "graph TD\n  A[Ingest] --> B[Transform] --> C[Archive]";
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
        assert!(svg.contains("Ingest"));
        assert!(svg.contains("Transform"));
        assert!(svg.contains("Archive"));
        assert!(svg.contains("3 nodes, 2 edges"));

        // Invalid/empty graph must fail cleanly rather than emitting a placeholder
        assert!(op
            .execute(
                DataPayload::text("not a graph"),
                serde_json::json!({ "type": "mermaid" }),
                &ctx,
            )
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_documents_adversarial_slice_and_recursion_guards() {
        let ctx = ExecutionContext::new("t_doc_adv");

        // 1. Reversed brackets "]A[" / "}A{" / ")A(" previously panicked in parse_node_token!
        let diag_op = DiagramCompilerOp;
        for evil in ["]A[ --> B", "}A{ --> B", ")A( --> B", "][ --> ()"] {
            let res = diag_op
                .execute(
                    DataPayload::text(evil),
                    serde_json::json!({ "type": "mermaid" }),
                    &ctx,
                )
                .await;
            assert!(res.is_ok(), "reversed bracket input failed: {evil}");
        }

        // 2. Deeply nested braces / \sqrt previously caused stack overflow in MathTypesetOp!
        let math_op = MathTypesetOp;
        let deep_braces = format!("{}{}", "{".repeat(500), "}".repeat(500));
        assert!(math_op
            .execute(
                DataPayload::text(deep_braces),
                serde_json::json!({ "format": "mathml" }),
                &ctx,
            )
            .await
            .is_err());

        let deep_sqrt = format!("{}x", r"\sqrt ".repeat(200));
        assert!(math_op
            .execute(
                DataPayload::text(deep_sqrt),
                serde_json::json!({ "format": "svg" }),
                &ctx,
            )
            .await
            .is_err());

        // Escaped braces \{ \} must render cleanly
        let escaped = math_op
            .execute(
                DataPayload::text(r"\{ x \}"),
                serde_json::json!({ "format": "mathml" }),
                &ctx,
            )
            .await
            .unwrap()
            .into_text()
            .unwrap();
        assert!(escaped.contains("<mo>{</mo>") && escaped.contains("<mo>}</mo>"));

        // 3. DocumentTranscodeOp LaTeX, Man, and error handling
        let trans = DocumentTranscodeOp;
        let latex = trans
            .execute(
                DataPayload::text("# Intro\n## Details\nBody"),
                serde_json::json!({ "from": "markdown", "to": "latex" }),
                &ctx,
            )
            .await
            .unwrap()
            .into_text()
            .unwrap();
        assert!(latex.contains(r"\section{Intro}") && latex.contains(r"\subsection{Details}"));

        let man = trans
            .execute(
                DataPayload::text("# Name\n## Synopsis"),
                serde_json::json!({ "from": "md", "to": "man" }),
                &ctx,
            )
            .await
            .unwrap()
            .into_text()
            .unwrap();
        assert!(man.contains(".SH NAME") && man.contains(".SS Synopsis"));

        assert!(trans
            .execute(
                DataPayload::text("hi"),
                serde_json::json!({ "from": "markdown", "to": "docx" }),
                &ctx,
            )
            .await
            .is_err());

        // 4. FontToolkitOp malformed input rejection
        assert!(FontToolkitOp
            .execute(
                DataPayload::bytes(b"not a ttf font"),
                serde_json::json!({}),
                &ctx
            )
            .await
            .is_err());
    }
}
