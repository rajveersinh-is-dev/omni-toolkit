use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniError, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use regex::Regex;
use serde_json::Value;

pub struct RegexStudioOp;

#[async_trait]
impl Operation for RegexStudioOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "text.regex_studio",
            "Regex Studio",
            "Interactive regular expression matcher, capture group inspector, replacement preview, and ReDoS diagnostic",
            OperationCategory::TextAndCode,
        )
        .with_types(vec![DataType::Text], vec![DataType::Json])
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let pattern = config.get("pattern").and_then(|v| v.as_str()).unwrap_or(".*");
        let replacement = config.get("replace").and_then(|v| v.as_str());

        // Simple heuristic ReDoS / Catastrophic backtracking warning:
        // Nested quantifiers like (a+)+ or (x*)* or (.*a)+
        let mut warnings = Vec::new();
        if pattern.contains(")+") || pattern.contains(")*") || pattern.contains("}+") {
            warnings.push("Potential catastrophic backtracking detected: pattern contains nested repetition operators.".to_string());
        }

        let re = Regex::new(pattern).map_err(|e| OmniError::InvalidInput(format!("Regex compile error: {e}")))?;
        let text = input.into_text()?;

        let mut matches = Vec::new();
        for m in re.find_iter(&text) {
            matches.push(serde_json::json!({
                "match": m.as_str(),
                "start": m.start(),
                "end": m.end()
            }));
        }

        let replaced_text = replacement.map(|r| re.replace_all(&text, r).to_string());

        let res = serde_json::json!({
            "pattern": pattern,
            "total_matches": matches.len(),
            "matches": matches,
            "replaced_output": replaced_text,
            "warnings": warnings,
        });

        Ok(DataPayload::json(res))
    }
}
