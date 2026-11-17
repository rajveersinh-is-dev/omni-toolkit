use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniError, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use serde_json::Value;

pub struct QueryStructuredOp;

#[async_trait]
impl Operation for QueryStructuredOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "query.structured",
            "Structured Query & Extraction (jq / JSONPath)",
            "Extracts and queries nested fields in JSON using path expressions",
            OperationCategory::TextAndCode,
        )
        .with_types(vec![DataType::Json, DataType::Text], vec![DataType::Json, DataType::Text])
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let path = config.get("query").and_then(|v| v.as_str()).unwrap_or(".");
        let json_val = input.into_json()?;

        // Clean path selector (e.g. .users[0].name or users.name)
        let trimmed = path.trim_start_matches('.');
        if trimmed.is_empty() {
            return Ok(DataPayload::json(json_val));
        }

        let mut current = &json_val;
        for part in trimmed.split('.') {
            if part.contains('[') && part.ends_with(']') {
                let open_idx = part.find('[').unwrap();
                let key = &part[..open_idx];
                let idx_str = &part[open_idx + 1..part.len() - 1];
                let idx: usize = idx_str.parse().map_err(|e| OmniError::InvalidInput(format!("Invalid array index: {e}")))?;

                if !key.is_empty() {
                    current = current.get(key).ok_or_else(|| OmniError::NotFound(format!("Key '{key}' not found")))?;
                }
                current = current.get(idx).ok_or_else(|| OmniError::NotFound(format!("Index '{idx}' out of bounds")))?;
            } else {
                current = current.get(part).ok_or_else(|| OmniError::NotFound(format!("Key '{part}' not found")))?;
            }
        }

        Ok(DataPayload::json(current.clone()))
    }
}
