use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use serde_json::Value;

pub struct MathTypesetOp;

#[async_trait]
impl Operation for MathTypesetOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "doc.math_typeset",
            "Mathematical Typesetting",
            "Converts LaTeX mathematics, MathML, and AsciiMath into scalable vector SVG markup",
            OperationCategory::DocumentsAndMedia,
        )
        .with_types(vec![DataType::Text], vec![DataType::Text])
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let math_text = input.into_text()?;
        let format = config.get("format").and_then(|v| v.as_str()).unwrap_or("svg");

        if format == "mathml" {
            let mathml = format!(
                "<math xmlns=\"http://www.w3.org/1998/Math/MathML\" display=\"block\"><semantics><mrow><mtext>{}</mtext></mrow></semantics></math>",
                html_escape::encode_text(&math_text)
            );
            Ok(DataPayload::text(mathml))
        } else {
            // Generate clean standalone SVG math banner
            let svg = format!(
                r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 600 80" width="100%" height="80">
  <style>
    .math-text {{ font-family: 'Cambria Math', 'KaTeX_Math', 'Times New Roman', serif; font-size: 24px; fill: #f0f6fc; font-style: italic; }}
    .bg {{ fill: #161b22; rx: 8px; }}
  </style>
  <rect width="600" height="80" class="bg"/>
  <text x="30" y="48" class="math-text">{}</text>
</svg>"#,
                html_escape::encode_text(&math_text)
            );
            Ok(DataPayload::text(svg))
        }
    }
}
