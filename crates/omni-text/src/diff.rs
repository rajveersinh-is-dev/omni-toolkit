use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, InputPortSpec, OmniResult,
    Operation, OperationCategory, OperationManifest,
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
            "Computes Myers line, word, or character diffs (supports single-input with config.original OR multi-input DAG ports 'original' & 'modified')",
            OperationCategory::TextAndCode,
        )
        .with_types(
            vec![DataType::Text, DataType::Json, DataType::Multi],
            vec![DataType::Text, DataType::Json],
        )
        .with_input_ports(vec![
            InputPortSpec {
                name: "original".into(),
                required: true,
                accepted_types: vec![DataType::Text, DataType::Json],
                description: "Baseline/original text".into(),
            },
            InputPortSpec {
                name: "modified".into(),
                required: true,
                accepted_types: vec![DataType::Text, DataType::Json],
                description: "Modified/target text".into(),
            },
        ])
        .with_status(FeatureStatus::Verified)
        .with_tags(vec!["text".into(), "diff".into(), "myers".into()])
    }

    async fn execute(
        &self,
        input: DataPayload,
        config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let (owned_a, owned_b) = match input {
            DataPayload::Multi(mut map) => {
                let a = map
                    .remove("original")
                    .map(|p| p.into_text())
                    .transpose()?
                    .unwrap_or_default();
                let b = map
                    .remove("modified")
                    .map(|p| p.into_text())
                    .transpose()?
                    .unwrap_or_default();
                (a, b)
            }
            single => {
                let a = config
                    .get("original")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let b = single.into_text()?;
                (a, b)
            }
        };

        let text_a = owned_a.as_str();
        let text_b = owned_b.as_str();
        let granularity = config
            .get("granularity")
            .and_then(|v| v.as_str())
            .unwrap_or("lines");

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
