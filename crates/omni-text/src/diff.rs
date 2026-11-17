use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use serde_json::Value;
use similar::{ChangeTag, TextDiff};

pub struct TextDiffOp;

#[async_trait]
impl Operation for TextDiffOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "text.diff",
            "Text Diff & Analysis",
            "Computes Myers, Histogram, and word/char diffs showing additions, deletions, and modifications",
            OperationCategory::TextAndCode,
        )
        .with_types(vec![DataType::Text, DataType::Json], vec![DataType::Text, DataType::Json])
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let text_a = config.get("original").and_then(|v| v.as_str()).unwrap_or("");
        let text_b = input.as_str().unwrap_or("");
        let granularity = config.get("granularity").and_then(|v| v.as_str()).unwrap_or("lines");

        let mut diff_output = String::new();

        if granularity == "chars" {
            let diff = TextDiff::from_chars(text_a, text_b);
            for change in diff.iter_all_changes() {
                let sign = match change.tag() {
                    ChangeTag::Delete => "-",
                    ChangeTag::Insert => "+",
                    ChangeTag::Equal => " ",
                };
                diff_output.push_str(&format!("{}{}", sign, change.value()));
            }
        } else if granularity == "words" {
            let diff = TextDiff::from_words(text_a, text_b);
            for change in diff.iter_all_changes() {
                let sign = match change.tag() {
                    ChangeTag::Delete => "[-",
                    ChangeTag::Insert => "{+",
                    ChangeTag::Equal => "",
                };
                let end = match change.tag() {
                    ChangeTag::Delete => "]",
                    ChangeTag::Insert => "}",
                    ChangeTag::Equal => "",
                };
                diff_output.push_str(&format!("{}{}{}", sign, change.value(), end));
            }
        } else {
            let diff = TextDiff::from_lines(text_a, text_b);
            for change in diff.iter_all_changes() {
                let sign = match change.tag() {
                    ChangeTag::Delete => "-",
                    ChangeTag::Insert => "+",
                    ChangeTag::Equal => " ",
                };
                diff_output.push_str(&format!("{}{}", sign, change));
            }
        }

        Ok(DataPayload::text(diff_output))
    }
}
