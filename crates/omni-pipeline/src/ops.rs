//! Built-in multi-input pipeline operations for joining, merging, and concatenating
//! multiple parent node streams deterministically in a DAG.

use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
};
use omni_registry::OperationRegistry;
use serde_json::{Map, Value};
use std::sync::Arc;

/// Merges multiple parent outputs into a single structured JSON object keyed by input port / node ID.
pub struct PipelineMergeOp;

#[async_trait]
impl Operation for PipelineMergeOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "pipeline.merge",
            "Pipeline Multi-Input JSON Merge",
            "Joins outputs from multiple parent DAG nodes into a single deterministic JSON object keyed by port name",
            OperationCategory::TextAndCode,
        )
        .with_types(vec![DataType::Any], vec![DataType::Json])
        .with_multi_input(true)
        .with_status(FeatureStatus::Verified)
        .with_tags(vec!["pipeline".into(), "join".into(), "merge".into()])
    }

    async fn execute(
        &self,
        input: DataPayload,
        _config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        match input {
            DataPayload::Multi(map) => {
                let mut obj = Map::new();
                for (key, payload) in map {
                    let val = match payload {
                        DataPayload::Json(v) => v,
                        DataPayload::Text(s) => Value::String(s),
                        DataPayload::Bytes(b) => match String::from_utf8(b.clone()) {
                            Ok(s) => Value::String(s),
                            Err(_) => Value::String(format!("bytes:{}", b.len())),
                        },
                        DataPayload::FileRef(p) => Value::String(p.display().to_string()),
                        DataPayload::Multi(inner) => serde_json::to_value(inner).map_err(|e| {
                            OmniError::Execution {
                                operation: "pipeline.merge".into(),
                                message: e.to_string(),
                            }
                        })?,
                    };
                    obj.insert(key, val);
                }
                Ok(DataPayload::json(Value::Object(obj)))
            }
            single => {
                let mut obj = Map::new();
                let val = serde_json::to_value(single).map_err(|e| OmniError::Execution {
                    operation: "pipeline.merge".into(),
                    message: e.to_string(),
                })?;
                obj.insert("input".to_string(), val);
                Ok(DataPayload::json(Value::Object(obj)))
            }
        }
    }
}

/// Concatenates multiple text/byte parent outputs in deterministic port order.
pub struct PipelineConcatOp;

#[async_trait]
impl Operation for PipelineConcatOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "pipeline.concat",
            "Pipeline Multi-Input Concatenation",
            "Concatenates outputs from multiple parent DAG nodes in deterministic port order with an optional separator",
            OperationCategory::TextAndCode,
        )
        .with_types(vec![DataType::Text, DataType::Bytes, DataType::Json], vec![DataType::Text])
        .with_multi_input(true)
        .with_status(FeatureStatus::Verified)
        .with_tags(vec!["pipeline".into(), "join".into(), "concat".into()])
    }

    async fn execute(
        &self,
        input: DataPayload,
        config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let separator = config
            .get("separator")
            .and_then(|v| v.as_str())
            .unwrap_or("\n");

        match input {
            DataPayload::Multi(map) => {
                let mut parts = Vec::with_capacity(map.len());
                for (_, payload) in map {
                    parts.push(payload.into_text()?);
                }
                Ok(DataPayload::text(parts.join(separator)))
            }
            single => Ok(DataPayload::text(single.into_text()?)),
        }
    }
}

pub fn register_pipeline_ops(registry: &mut OperationRegistry) -> OmniResult<()> {
    registry.register(Arc::new(PipelineMergeOp))?;
    registry.register(Arc::new(PipelineConcatOp))?;
    Ok(())
}
