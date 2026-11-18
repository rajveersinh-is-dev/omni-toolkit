use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
};
use serde_json::Value;

pub struct QueryStructuredOp;

#[async_trait]
impl Operation for QueryStructuredOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "query.structured",
            "Structured Query & Extraction (jq / JSONPath)",
            "Extracts and queries nested fields and array indices in JSON using jq/JSONPath expressions",
            OperationCategory::TextAndCode,
        )
        .with_types(
            vec![DataType::Json, DataType::Text],
            vec![DataType::Json, DataType::Text],
        )
        .with_status(FeatureStatus::Verified)
        .with_tags(vec!["text".into(), "json".into(), "jq".into(), "jsonpath".into()])
    }

    async fn execute(
        &self,
        input: DataPayload,
        config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let path = config.get("query").and_then(|v| v.as_str()).unwrap_or(".");
        let json_val = input.into_json()?;

        // Support optional leading `$` and `.` (e.g. `$.users[0].name`, `.users[0].name`, `matrix[0][1]`)
        let trimmed = path.trim().trim_start_matches('$').trim_start_matches('.');
        if trimmed.is_empty() {
            return Ok(DataPayload::json(json_val));
        }

        let mut current = &json_val;
        for part in trimmed.split('.') {
            if part.is_empty() {
                continue;
            }
            if let Some(open_idx) = part.find('[') {
                let key = &part[..open_idx];
                if !key.is_empty() {
                    current = current
                        .get(key)
                        .ok_or_else(|| OmniError::NotFound(format!("Key '{key}' not found")))?;
                }
                let mut rest = &part[open_idx..];
                while !rest.is_empty() {
                    let Some(stripped) = rest.strip_prefix('[') else {
                        return Err(OmniError::InvalidInput(format!(
                            "Malformed index segment '{part}'"
                        )));
                    };
                    let Some(close_idx) = stripped.find(']') else {
                        return Err(OmniError::InvalidInput(format!(
                            "Unclosed '[' in query segment '{part}'"
                        )));
                    };
                    let idx_str = &stripped[..close_idx];
                    let idx: usize = idx_str.parse().map_err(|e| {
                        OmniError::InvalidInput(format!("Invalid array index '{idx_str}': {e}"))
                    })?;
                    current = current.get(idx).ok_or_else(|| {
                        OmniError::NotFound(format!("Index '{idx}' out of bounds"))
                    })?;
                    rest = &stripped[close_idx + 1..];
                }
            } else {
                current = current
                    .get(part)
                    .ok_or_else(|| OmniError::NotFound(format!("Key '{part}' not found")))?;
            }
        }

        Ok(DataPayload::json(current.clone()))
    }
}
