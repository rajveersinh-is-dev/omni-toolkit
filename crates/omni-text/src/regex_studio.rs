use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
};
use regex::RegexBuilder;
use serde_json::Value;

const MAX_REGEX_COMPILE_BYTES: usize = 10 * 1024 * 1024;
const MAX_RETURNED_MATCHES: usize = 10_000;

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
        .with_status(FeatureStatus::Verified)
        .with_tags(vec!["text".into(), "regex".into(), "captures".into(), "redos".into()])
    }

    async fn execute(
        &self,
        input: DataPayload,
        config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let pattern = config
            .get("pattern")
            .and_then(|v| v.as_str())
            .unwrap_or(".*");
        let replacement = config.get("replace").and_then(|v| v.as_str());

        // Simple heuristic ReDoS / Catastrophic backtracking warning:
        // Nested quantifiers like (a+)+ or (x*)* or (.*a)+
        let mut warnings = Vec::new();
        if pattern.contains(")+") || pattern.contains(")*") || pattern.contains("}+") {
            warnings.push(
                "Potential catastrophic backtracking detected in backtracking engines: pattern contains nested repetition operators.".to_string(),
            );
        }

        let re = RegexBuilder::new(pattern)
            .size_limit(MAX_REGEX_COMPILE_BYTES)
            .build()
            .map_err(|e| OmniError::InvalidInput(format!("Regex compile error: {e}")))?;
        let text = input.into_text()?;

        let mut matches = Vec::new();
        let mut total_matches = 0usize;
        for caps in re.captures_iter(&text) {
            total_matches += 1;
            if matches.len() < MAX_RETURNED_MATCHES {
                if let Some(full) = caps.get(0) {
                    let groups: Vec<Option<&str>> = (1..caps.len())
                        .map(|i| caps.get(i).map(|m| m.as_str()))
                        .collect();
                    matches.push(serde_json::json!({
                        "match": full.as_str(),
                        "start": full.start(),
                        "end": full.end(),
                        "groups": groups,
                    }));
                }
            }
        }

        let replaced_text = replacement.map(|r| re.replace_all(&text, r).to_string());

        let res = serde_json::json!({
            "pattern": pattern,
            "total_matches": total_matches,
            "matches_truncated": total_matches > MAX_RETURNED_MATCHES,
            "matches": matches,
            "replaced_output": replaced_text,
            "warnings": warnings,
        });

        Ok(DataPayload::json(res))
    }
}
